# CipherLab CTF — Flask platform

A working local CTF learning platform with **54 seeded challenges**, accounts, flag validation, hints, scoring, difficulty/category filters, progress tracking, and a leaderboard. Challenges are offline, self-contained puzzle artifacts; they do not attack real systems or execute user-submitted code.

## Run locally
1. Install Python 3.11+.
2. `python -m venv .venv`
3. Activate it (`source .venv/bin/activate` on Linux/macOS; `.venv\\Scripts\\activate` on Windows).
4. `pip install -r requirements.txt`
5. Set a secret key, for example `export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"` (PowerShell: `$env:SECRET_KEY=...`).
6. `python app.py`
7. Open http://127.0.0.1:5000 and register an account.

SQLite database is created automatically at `ctf.sqlite3` (or `CTF_DB`). Seed challenges are inserted only when the challenge table is empty.

## Run with Docker Compose
1. Copy `.env.example` to `.env` and replace `SECRET_KEY` with a long random value.
2. `docker compose up --build -d`
3. Open http://127.0.0.1:5000
4. `docker compose logs -f ctf`; stop with `docker compose down`.

The web container runs as an unprivileged user, drops Linux capabilities, uses a read-only root filesystem, and stores SQLite data in a persistent volume.

## Important security notes
- This is a functional starter platform, not a security-audited public production service. Use HTTPS and a reverse proxy before exposing it publicly.
- Set a strong, unique `SECRET_KEY`; never use the fallback value in deployment.
- Add CSRF protection, rate limits, email verification, password reset, backup/restore, and admin moderation before public launch.
- Flags are stored as SHA-256 hashes, not plaintext. The challenges themselves are deliberately safe static exercises.
- **Docker isolation:** the included Compose configuration isolates the platform web process. No challenge container is launched because seeded challenges do not execute code. If you add exploit labs or downloadable binaries, run each lab in a separate disposable container/VM with no host mounts, no privileged mode, strict CPU/memory/PID limits, restricted networking, and explicit teardown. Never execute challenge submissions on the Flask host.
- The app binds to `127.0.0.1` for local Python runs. Docker runs Gunicorn on the container interface.
