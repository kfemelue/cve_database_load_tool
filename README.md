# cve_database_load_tool
Python Script to load CVEs from cvelistV5 into SQL database. 
Generated with ChatGPT 5.6-Sol

Data is sourced from the cvelistV5 github repo: [https://github.com/CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)


Run App Locally
```
pip install -r requirements.txt

# For first db load
python load_cves_latest.py

# For loading deltas
python load_cves_latest.py --release-type delta

```


Docker
```
docker build -t cve-loader .

# Initial Full Import

docker run --rm \
  --env-file .env \
  cve-loader

# Subsequent Data loads

docker run --rm \
  --env-file .env \
  cve-loader \
  --release-type delta

# OR

docker compose run --rm cve-loader --release-type delta

```


Container Flow
```
Docker container
      │
      ├── GitHub API
      │      │
      │      ▼
      │   latest CVE baseline ZIP
      │
      ▼
 Parse / batch CVEs
      │
      │ TLS
      ▼
 Neon PostgreSQL
      │
      ▼
 UPSERT cves
```
