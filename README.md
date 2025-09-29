# SQLi Scanner + VulnApp Dashboard

This workspace contains:
- vuln_webapp/ — an intentionally vulnerable PHP app (SQLite via PDO)
- app.py — an async SQL injection scanner tuned for SQLite/PDO errors
- dashboard.py — a small Flask UI to run scans and view results

## Prereqs
- Python 3.10+
- PHP 8 CLI (for the built-in server)

## Install Python deps

```powershell
cd d:\crawler_python
pip install -r requirements.txt
```

## Initialize and run the PHP VulnApp

```powershell
cd d:\crawler_python\vuln_webapp
php .\db_init.php
php -S localhost:8000
```

Leave it running. Open http://localhost:8000.

## Run the scanner from CLI (optional)

```powershell
cd d:\crawler_python
python .\app.py --start-url http://localhost:8000 --max-depth 2 --concurrency 10
```

Artifacts are saved as `scan_<timestamp>.json/csv` and `latest_scan.json`.

## Start the dashboard

Open a new terminal and run:

```powershell
cd d:\crawler_python
$env:START_URL = "http://localhost:8000"
python .\dashboard.py
```

Then open http://127.0.0.1:5050 to trigger scans and view results.
