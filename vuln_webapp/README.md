# VulnApp (SQLite)

Intentionally vulnerable PHP web application for local security testing. Do NOT expose to the internet.

## Requirements
- PHP 8+ CLI
- No MySQL needed (uses SQLite file `vulnapp.db`)

## Initialize the SQLite database
Run this once to create and seed `vulnapp.db`:

```powershell
# From the vuln_webapp directory
php .\db_init.php
```

This executes `schema.sql` and `seed.sql` to create tables and insert sample data.

## Run the app
Start the PHP built-in server from this directory:

```powershell
php -S localhost:8000
```

Then open http://localhost:8000 in your browser.

## Pages
- `/index.php` — list users and comments; GET search and POST comment (SQLi + XSS)
- `/login.php` — vulnerable login (SQLi)
- `/comment.php` — post comment (XSS)
- `/search.php` — search (SQLi)
- `/upload.php` — unrestricted file upload
- `/view_upload.php` — view file content from DB
- `/admin.php` — delete via GET/POST (CSRF + SQLi)
- `/exec.php` — command execution (command injection)

## Notes
- All inputs are intentionally unsanitized. This is for scanner/script testing only.
- Sample creds: admin/admin, alice/password123, bob/qwerty, eve/letmein