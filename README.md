# MAFIA Control

Key management panel with a public /connect endpoint (Flask, PostgreSQL or SQLite).

## Deploy on Render
1. Push this folder to a GitHub repository.
2. Render: New > Web Service > pick the repo (or New > Blueprint to use render.yaml).
3. Build command: pip install -r requirements.txt
4. Start command: gunicorn app:app --workers 1 --threads 4 --timeout 60
5. Environment variables:
   - DATABASE_URL: your Neon connection string (keeps keys safe across restarts)
   - SECRET_KEY: any long random text
   - ADMIN_USER and ADMIN_PASS: panel login
6. Open https://YOUR-NAME.onrender.com/login. The Connect tab shows the exact /connect URL.

Without DATABASE_URL the app uses a local SQLite file, which Render deletes on every restart.
