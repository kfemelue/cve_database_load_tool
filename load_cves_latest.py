
#!/usr/bin/env python3
"""
Download/load CVEProject/cvelistV5 release ZIPs into a SQL database.

By default this script discovers the newest full daily baseline ZIP from the
official GitHub Releases API, downloads it to a temporary directory, streams
CVE JSON records from the ZIP, and upserts them into SQL.

Configuration:
    Connection strings and secrets are loaded from a .env file.

    Required/optional .env variables:
        DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST/DB?sslmode=require
        GITHUB_TOKEN=             # optional; raises GitHub API rate limits

Examples:
    # Fresh database: download newest full baseline automatically.
    python load_cves_latest.py

    # Apply the newest hourly delta to an already-bootstrapped database.
    python load_cves_latest.py --release-type delta

    # Load a local file or direct ZIP URL.
    python load_cves_latest.py ./2026-09-16_all_CVEs_at_midnight.zip
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from dotenv import find_dotenv, load_dotenv
import psutil


GITHUB_RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
BASELINE_ASSET_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}_all_CVEs_at_midnight\.zip(?:\.zip)?$"
)
DELTA_ASSET_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}_delta_CVEs_at_\d{4}Z\.zip(?:\.zip)?$"
)
USER_AGENT = "cvelistV5-sql-loader/1.0"


class ProcessMetrics:
    """Track lightweight process-level performance metrics for one loader run."""

    def __init__(self, sample_interval: float = 0.5) -> None:
        self.sample_interval = sample_interval
        self.process = psutil.Process(os.getpid())
        self.started_at = 0.0
        self.start_cpu_user = 0.0
        self.start_cpu_system = 0.0
        self.cpu_samples: list[float] = []
        self.peak_rss = 0
        self.phases: dict[str, float] = {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        cpu_times = self.process.cpu_times()
        self.start_cpu_user = cpu_times.user
        self.start_cpu_system = cpu_times.system
        self.started_at = time.perf_counter()
        self.peak_rss = self.process.memory_info().rss

        # Prime psutil's non-blocking CPU percentage calculation.
        self.process.cpu_percent(interval=None)
        self._thread = threading.Thread(
            target=self._sample_loop,
            name="process-metrics",
            daemon=True,
        )
        self._thread.start()

    def _sample_loop(self) -> None:
        while not self._stop_event.wait(self.sample_interval):
            try:
                self.cpu_samples.append(self.process.cpu_percent(interval=None))
                self.peak_rss = max(self.peak_rss, self.process.memory_info().rss)
            except (psutil.Error, OSError):
                # Metrics should never cause an ingestion run to fail.
                return

    def record_phase(self, name: str, elapsed_seconds: float) -> None:
        self.phases[name] = elapsed_seconds

    def stop_and_report(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self.sample_interval + 0.5)

        elapsed = max(0.0, time.perf_counter() - self.started_at)
        try:
            cpu_times = self.process.cpu_times()
            cpu_user = max(0.0, cpu_times.user - self.start_cpu_user)
            cpu_system = max(0.0, cpu_times.system - self.start_cpu_system)
            cpu_total = cpu_user + cpu_system
            self.peak_rss = max(self.peak_rss, self.process.memory_info().rss)
        except (psutil.Error, OSError):
            cpu_user = cpu_system = cpu_total = 0.0

        sampled_avg = (
            sum(self.cpu_samples) / len(self.cpu_samples)
            if self.cpu_samples
            else 0.0
        )
        sampled_peak = max(self.cpu_samples, default=0.0)

        # This ratio is a useful whole-run CPU saturation metric. 100% means
        # approximately one logical CPU was busy for the entire wall-clock run.
        effective_cpu = (cpu_total / elapsed * 100.0) if elapsed > 0 else 0.0

        print("\nPerformance summary")
        print("-------------------")
        print(f"Total elapsed time:      {format_duration(elapsed)}")
        for phase, seconds in self.phases.items():
            print(f"{phase + ':':24} {format_duration(seconds)}")
        print(f"Process CPU time:        {format_duration(cpu_total)}")
        print(f"  user:                  {format_duration(cpu_user)}")
        print(f"  system:                {format_duration(cpu_system)}")
        print(f"Effective CPU usage:     {effective_cpu:,.1f}%")
        print(f"Average sampled CPU:     {sampled_avg:,.1f}%")
        print(f"Peak sampled CPU:        {sampled_peak:,.1f}%")
        print(f"Peak process memory:     {self.peak_rss / 1024 / 1024:,.1f} MiB")


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:,.2f}s"

    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {sec:05.2f}s"

    hours, minutes = divmod(int(minutes), 60)
    return f"{hours}h {minutes:02d}m {sec:05.2f}s"

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class Base(DeclarativeBase):
    pass


class CVE(Base):
    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    state: Mapped[str | None] = mapped_column(String(32), index=True)
    data_version: Mapped[str | None] = mapped_column(String(16))
    assigner_org_id: Mapped[str | None] = mapped_column(String(64))
    assigner_short_name: Mapped[str | None] = mapped_column(String(128), index=True)

    date_reserved: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    date_published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    date_updated: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)

    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    cvss_severity: Mapped[str | None] = mapped_column(String(32), index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    cvss_version: Mapped[str | None] = mapped_column(String(16))

    cwe_ids: Mapped[list[str] | None] = mapped_column(JSON)
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


def parse_datetime(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        # Works across Python versions that do not accept a trailing "Z".
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def english_text(items: Any, field: str = "value") -> str | None:
    if not isinstance(items, list):
        return None

    for item in items:
        if isinstance(item, dict) and item.get("lang") == "en" and item.get(field):
            return str(item[field])

    for item in items:
        if isinstance(item, dict) and item.get(field):
            return str(item[field])

    return None


def extract_cwes(cna: dict[str, Any]) -> list[str]:
    result: list[str] = []

    for problem_type in cna.get("problemTypes", []) or []:
        if not isinstance(problem_type, dict):
            continue
        for desc in problem_type.get("descriptions", []) or []:
            if not isinstance(desc, dict):
                continue

            cwe_id = desc.get("cweId")
            if isinstance(cwe_id, str) and cwe_id.startswith("CWE-"):
                result.append(cwe_id)

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(result))


def metric_containers(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}

    for metric in cna.get("metrics", []) or []:
        if isinstance(metric, dict):
            yield metric

    for adp in containers.get("adp", []) or []:
        if not isinstance(adp, dict):
            continue
        for metric in adp.get("metrics", []) or []:
            if isinstance(metric, dict):
                yield metric


def extract_cvss(record: dict[str, Any]) -> tuple[float | None, str | None, str | None, str | None]:
    # Prefer newer CVSS versions if a record contains multiple metrics.
    candidates = (
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
        ("cvssV2_0", "2.0"),
    )

    metrics = list(metric_containers(record))
    for key, version in candidates:
        for metric in metrics:
            cvss = metric.get(key)
            if not isinstance(cvss, dict):
                continue

            score = cvss.get("baseScore")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None

            severity = cvss.get("baseSeverity")
            vector = cvss.get("vectorString")

            return (
                score,
                str(severity) if severity is not None else None,
                str(vector) if vector is not None else None,
                version,
            )

    return None, None, None, None


def record_to_row(record: dict[str, Any]) -> dict[str, Any] | None:
    metadata = record.get("cveMetadata") or {}
    cve_id = metadata.get("cveId")

    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        return None

    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    if not isinstance(cna, dict):
        cna = {}

    score, severity, vector, cvss_version = extract_cvss(record)

    return {
        "cve_id": cve_id,
        "state": metadata.get("state"),
        "data_version": record.get("dataVersion"),
        "assigner_org_id": metadata.get("assignerOrgId"),
        "assigner_short_name": metadata.get("assignerShortName"),
        "date_reserved": parse_datetime(metadata.get("dateReserved")),
        "date_published": parse_datetime(metadata.get("datePublished")),
        "date_updated": parse_datetime(metadata.get("dateUpdated")),
        "title": cna.get("title"),
        "description": english_text(cna.get("descriptions")),
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cvss_version": cvss_version,
        "cwe_ids": extract_cwes(cna),
        "raw_json": record,
        "ingested_at": datetime.now(timezone.utc),
    }


def upsert_batch(session: Session, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return

    table = CVE.__table__
    dialect = session.bind.dialect.name
    update_columns = [
        column.name
        for column in table.columns
        if column.name != "cve_id"
    ]

    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert

        stmt = insert(table).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=[table.c.cve_id],
            set_={name: getattr(stmt.excluded, name) for name in update_columns},
        )
        session.execute(stmt)

    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert

        stmt = insert(table).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=[table.c.cve_id],
            set_={name: getattr(stmt.excluded, name) for name in update_columns},
        )
        session.execute(stmt)

    elif dialect in {"mysql", "mariadb"}:
        from sqlalchemy.dialects.mysql import insert

        stmt = insert(table).values(rows)
        stmt = stmt.on_duplicate_key_update(
            **{name: getattr(stmt.inserted, name) for name in update_columns}
        )
        session.execute(stmt)

    else:
        # Generic fallback for other SQLAlchemy-supported SQL databases.
        for row in rows:
            session.merge(CVE(**row))


def is_cve_member(name: str) -> bool:
    base = Path(name).name
    return base.startswith("CVE-") and base.endswith(".json")


def archive_contains_cves(zip_path: Path) -> bool:
    """Return True when a ZIP directly contains CVE JSON records."""
    with zipfile.ZipFile(zip_path) as archive:
        return any(
            not member.is_dir() and is_cve_member(member.filename)
            for member in archive.infolist()
        )


def prepare_cve_zip(
    zip_path: Path,
    temp_dir: tempfile.TemporaryDirectory[str] | None = None,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    """Resolve GitHub's occasionally nested baseline artifact ZIP.

    cvelistV5's baseline workflow uploads ``cves.zip`` as a GitHub Actions
    artifact. GitHub wraps artifacts in another ZIP archive, and the current
    release workflow can publish that wrapper with a ``.zip.zip`` name. In
    that case the downloaded release asset contains ``cves.zip`` rather than
    CVE JSON files directly.

    This function unwraps nested ZIPs to disk (not memory) until the archive
    directly contains CVE JSON records.
    """
    current = zip_path

    for depth in range(3):
        if archive_contains_cves(current):
            return current, temp_dir

        with zipfile.ZipFile(current) as archive:
            nested = [
                member
                for member in archive.infolist()
                if not member.is_dir()
                and member.filename.lower().endswith(".zip")
            ]

            if not nested:
                raise RuntimeError(
                    f"ZIP does not contain CVE JSON records: {current.name}"
                )

            # Prefer the canonical payload produced by the baseline workflow.
            nested.sort(
                key=lambda member: (
                    Path(member.filename).name.lower() != "cves.zip",
                    member.filename,
                )
            )
            member = nested[0]

            if temp_dir is None:
                temp_dir = tempfile.TemporaryDirectory(prefix="cvelistv5-")

            inner_name = Path(member.filename).name
            inner_path = Path(temp_dir.name) / f"nested-{depth}-{inner_name}"
            print(f"Unwrapping nested CVE archive: {member.filename}")

            with archive.open(member) as src, inner_path.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)

        if not zipfile.is_zipfile(inner_path):
            raise RuntimeError(
                f"Nested archive is not a valid ZIP: {member.filename}"
            )

        current = inner_path

    raise RuntimeError(
        f"Too many nested ZIP layers while resolving {zip_path.name}"
    )


def iter_cve_records(zip_path: Path) -> Iterator[dict[str, Any]]:
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            if member.is_dir() or not is_cve_member(member.filename):
                continue

            try:
                with archive.open(member) as f:
                    record = json.load(f)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                print(f"Skipping invalid JSON {member.filename}: {exc}", file=sys.stderr)
                continue

            if isinstance(record, dict):
                yield record


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }

    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers


def fetch_github_json(url: str) -> Any:
    request = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def asset_matches(name: str, release_type: str) -> bool:
    if release_type == "baseline":
        return bool(BASELINE_ASSET_RE.fullmatch(name))
    if release_type == "delta":
        return bool(DELTA_ASSET_RE.fullmatch(name))
    if release_type == "latest":
        return bool(
            BASELINE_ASSET_RE.fullmatch(name)
            or DELTA_ASSET_RE.fullmatch(name)
        )
    raise ValueError(f"Unsupported release type: {release_type}")


def find_latest_release_asset(release_type: str) -> dict[str, Any]:
    # Releases are returned newest first. A daily baseline should be within the
    # first page because the project publishes hourly releases. We still page
    # a few times so the script is resilient to unusual release activity.
    seen_zip_assets: list[str] = []

    for page in range(1, 4):
        query = urllib.parse.urlencode({"per_page": 100, "page": page})
        releases = fetch_github_json(f"{GITHUB_RELEASES_API}?{query}")

        if not isinstance(releases, list):
            raise RuntimeError("Unexpected response from GitHub Releases API")

        for release in releases:
            if not isinstance(release, dict) or release.get("draft"):
                continue

            assets = release.get("assets") or []
            for asset in assets:
                if not isinstance(asset, dict):
                    continue

                name = asset.get("name")
                download_url = asset.get("browser_download_url")

                if isinstance(name, str) and name.lower().endswith(".zip"):
                    if len(seen_zip_assets) < 20:
                        seen_zip_assets.append(name)

                if (
                    isinstance(name, str)
                    and isinstance(download_url, str)
                    and asset_matches(name, release_type)
                ):
                    return {
                        "name": name,
                        "url": download_url,
                        "release_name": release.get("name") or release.get("tag_name"),
                        "published_at": release.get("published_at"),
                    }

        if len(releases) < 100:
            break

    observed = ", ".join(dict.fromkeys(seen_zip_assets)) or "none"
    raise RuntimeError(
        f"Could not find a recent cvelistV5 {release_type!r} ZIP asset. "
        f"Recent ZIP asset names observed: {observed}"
    )


def download_zip(url: str, filename: str) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
    temp_dir = tempfile.TemporaryDirectory(prefix="cvelistv5-")
    target = Path(temp_dir.name) / filename

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    print(f"Downloading {filename}")

    try:
        with urllib.request.urlopen(request, timeout=60) as response, target.open("wb") as out:
            total = response.headers.get("Content-Length")
            total_bytes = int(total) if total and total.isdigit() else None
            downloaded = 0

            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                downloaded += len(chunk)

                if total_bytes:
                    pct = downloaded / total_bytes * 100
                    print(
                        f"\rDownloaded {downloaded / 1024 / 1024:,.1f} MiB "
                        f"({pct:5.1f}%)",
                        end="",
                        flush=True,
                    )
                else:
                    print(
                        f"\rDownloaded {downloaded / 1024 / 1024:,.1f} MiB",
                        end="",
                        flush=True,
                    )
    except Exception:
        temp_dir.cleanup()
        raise

    print()

    if not zipfile.is_zipfile(target):
        temp_dir.cleanup()
        raise RuntimeError(f"Downloaded file is not a valid ZIP: {filename}")

    try:
        return prepare_cve_zip(target, temp_dir)
    except Exception:
        temp_dir.cleanup()
        raise


def obtain_zip(
    source: str | None,
    release_type: str,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if source is None:
        asset = find_latest_release_asset(release_type)
        print(
            "Selected release asset: "
            f"{asset['name']} "
            f"({asset.get('release_name') or 'unknown release'})"
        )
        return download_zip(asset["url"], asset["name"])

    if source.startswith(("http://", "https://")):
        filename = Path(urllib.parse.urlparse(source).path).name or "release.zip"
        return download_zip(source, filename)

    path = Path(source).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(path)
    if not zipfile.is_zipfile(path):
        raise RuntimeError(f"Not a valid ZIP file: {path}")
    return prepare_cve_zip(path)


def normalize_database_url(database_url: str) -> str:
    """Allow Neon's standard PostgreSQL URL to work with Psycopg 3.

    Neon typically provides a URL beginning with ``postgresql://``. SQLAlchemy
    uses the driver-qualified ``postgresql+psycopg://`` form to select Psycopg 3.
    Query parameters such as ``sslmode=require`` and ``channel_binding=require``
    are preserved unchanged.
    """
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url[len("postgres://"):]
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url[len("postgresql://"):]
    return database_url


def build_engine(database_url: str) -> Engine:
    return create_engine(
        normalize_database_url(database_url),
        future=True,
        pool_pre_ping=True,
        pool_recycle=300,
    )


def verify_database_connection(engine: Engine) -> None:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    print("Database connection verified.")


def load_zip(zip_path: Path, engine: Engine, batch_size: int) -> tuple[int, int]:
    Base.metadata.create_all(engine)

    processed = 0
    skipped = 0
    batch: list[dict[str, Any]] = []

    with Session(engine) as session:
        for record in iter_cve_records(zip_path):
            row = record_to_row(record)
            if row is None:
                skipped += 1
                continue

            batch.append(row)

            if len(batch) >= batch_size:
                upsert_batch(session, batch)
                session.commit()
                processed += len(batch)
                print(f"\rLoaded {processed:,} CVEs", end="", flush=True)
                batch.clear()

        if batch:
            upsert_batch(session, batch)
            session.commit()
            processed += len(batch)

    print()
    return processed, skipped


def run_loader(metrics: ProcessMetrics) -> int:
    # Load .env before reading any connection strings or secrets. Search from
    # the current working directory so project-local .env files work even when
    # this script is invoked by absolute path. Existing process environment
    # variables take precedence over values in .env.
    dotenv_path = find_dotenv(usecwd=True)
    if dotenv_path:
        load_dotenv(dotenv_path=dotenv_path, override=False)

    parser = argparse.ArgumentParser(
        description="Load a cvelistV5 release ZIP into a SQL database."
    )
    parser.add_argument(
        "zip_source",
        nargs="?",
        default=None,
        help=(
            "Optional local ZIP path or direct HTTP(S) URL. If omitted, the "
            "script discovers and downloads a ZIP from the official GitHub releases."
        ),
    )
    parser.add_argument(
        "--release-type",
        choices=("baseline", "delta", "latest"),
        default="baseline",
        help=(
            "Asset to download when zip_source is omitted: baseline = newest full "
            "daily dataset (default), delta = newest hourly delta, latest = newest "
            "matching baseline or delta ZIP."
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Rows per upsert transaction (default: 100).",
    )

    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        parser.error(
            "DATABASE_URL is not set. Add it to a .env file, for example: "
            "DATABASE_URL=sqlite:///cves.db"
        )

    engine = build_engine(database_url)
    temp_dir = None
    try:
        phase_start = time.perf_counter()
        verify_database_connection(engine)
        metrics.record_phase(
            "Database connection", time.perf_counter() - phase_start
        )

        phase_start = time.perf_counter()
        zip_path, temp_dir = obtain_zip(args.zip_source, args.release_type)
        metrics.record_phase(
            "Download/archive prep", time.perf_counter() - phase_start
        )

        phase_start = time.perf_counter()
        loaded, skipped = load_zip(zip_path, engine, args.batch_size)
        metrics.record_phase("CVE database load", time.perf_counter() - phase_start)

        print(f"Done. Upserted {loaded:,} CVEs; skipped {skipped:,} records.")
        return 0
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()
        engine.dispose()


def main() -> int:
    metrics = ProcessMetrics()
    metrics.start()
    try:
        return run_loader(metrics)
    finally:
        metrics.stop_and_report()


if __name__ == "__main__":
    raise SystemExit(main())

