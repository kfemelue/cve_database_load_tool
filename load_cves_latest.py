
#!/usr/bin/env python3
"""
Download/load CVEProject/cvelistV5 release ZIPs into a SQL database.

By default this script discovers the newest full daily baseline ZIP from the
official GitHub Releases API, downloads it to a temporary directory, streams
CVE JSON records from the ZIP, and upserts them into SQL.

Examples:
    # Fresh database: download newest full baseline automatically.
    python load_cves_latest.py --database-url sqlite:///cves.db

    # PostgreSQL fresh load.
    python load_cves_latest.py \
        --database-url postgresql+psycopg://user:pass@localhost/cves

    # Apply the newest hourly delta to an already-bootstrapped database.
    python load_cves_latest.py --release-type delta \
        --database-url postgresql+psycopg://user:pass@localhost/cves

    # Backward compatible: load a local file or direct ZIP URL.
    python load_cves_latest.py ./2026-09-16_all_CVEs_at_midnight.zip \
        --database-url sqlite:///cves.db

Set GITHUB_TOKEN in the environment if you want authenticated GitHub API
requests (useful for higher API rate limits).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


GITHUB_RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
BASELINE_ASSET_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_all_CVEs_at_midnight\.zip$")
DELTA_ASSET_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_delta_CVEs_at_\d{4}Z\.zip$")
USER_AGENT = "cvelistV5-sql-loader/1.0"

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    String,
    Text,
    create_engine,
)
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

    raise RuntimeError(
        f"Could not find a recent cvelistV5 {release_type!r} ZIP asset."
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

    return target, temp_dir


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
    return path, None


def load_zip(zip_path: Path, database_url: str, batch_size: int) -> tuple[int, int]:
    engine = create_engine(database_url, future=True)
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


def main() -> int:
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
        "--database-url",
        default=os.getenv("DATABASE_URL", "sqlite:///cves.db"),
        help=(
            "SQLAlchemy database URL. Defaults to DATABASE_URL, "
            "or sqlite:///cves.db if unset."
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

    temp_dir = None
    try:
        zip_path, temp_dir = obtain_zip(args.zip_source, args.release_type)
        loaded, skipped = load_zip(zip_path, args.database_url, args.batch_size)
        print(f"Done. Upserted {loaded:,} CVEs; skipped {skipped:,} records.")
        return 0
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
