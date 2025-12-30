# AIML_DBMS
# AIML_DBMS

This repository contains a covert-channel demo, data ingestion scripts, a small Flask webapp that exposes SQL and Mongo read endpoints, and utilities to migrate/seed data.

This README explains how to set up the project on another machine and run the webapp and pipeline components.

## Prerequisites
- macOS / Linux / Windows with Python 3.9+ installed
- MySQL server (or compatible) accessible from the host where you run the scripts
- MongoDB server accessible from the host where you run the scripts
- git (to clone the repo)

## Quick start (recommended)
1. Clone the repository

   ```bash
   git clone <repo-url>
   cd AIML_DBMS/aiml_dbms_lab
   ```

2. Create and activate a Python virtual environment

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate    # macOS / Linux (zsh/bash)
   .\.venv\Scripts\activate   # Windows (PowerShell/CMD)
   ```

3. Install Python dependencies

   ```bash
   # If you have a requirements.txt, use it; otherwise install these packages:
   pip install flask flask-cors pymysql pymongo
   ```

4. Configure environment variables

Set these environment variables before running the webapp or ingestion scripts. You can export them in your shell or use a .env loader if you prefer.

- MYSQL_HOST (default: localhost)
- MYSQL_USER (default: root)
- MYSQL_PASS (default: empty)
- MYSQL_DB   (default: COVERT_CHANNEL)
- MONGO_URI  (default: mongodb://localhost:27017)
- MONGO_DB   (default: covert_channel)
- SECRET_KEY (Flask session secret; default: change-me)
- AUTH_USER  (web UI username; default: admin)
- AUTH_PASS  (web UI password; default: admin)
- PORT       (port for the Flask app; default: 5003)

Example (macOS / Linux):

   ```bash
   export MYSQL_HOST=localhost
   export MYSQL_USER=root
   export MYSQL_PASS=your_mysql_password
   export MYSQL_DB=COVERT_CHANNEL
   export MONGO_URI='mongodb://localhost:27017'
   export MONGO_DB=covert_channel
   export SECRET_KEY='replace-with-a-secret'
   export AUTH_USER=admin
   export AUTH_PASS=admin
   export PORT=5003
   ```

## Database preparation
- The repository contains scripts under `InsertDatabase/` to insert flows, packets and attacks into your MySQL database. Those scripts expect the database schema to exist. If you have a SQL schema dump, import it into the `MYSQL_DB` database before running insert scripts.
- The `NoSQL/seed_vulnerabilities.py` script seeds the `vulnerabilities` collection in Mongo. The `NoSQL/migrate_attacks_to_mongo.py` copies attacks into Mongo and links vulnerabilities.

## Running the ingestion / demo pipeline (end-to-end)
- Capture, send, build and insert scripts are available under `CapturePackets/`, `SendPackets/`, `InsertDatabase/` and `NoSQL/`.
- The precise order used during development was roughly:
  1. (optional) run capture scripts in `CapturePackets/` to capture sample packets
  2. run send scripts in `SendPackets/` to generate covert traffic (these are demos and assume a lab/test environment)
  3. run `build_flow_table.py` in `CapturePackets/` to build flow JSON data
  4. run INSERT scripts in `InsertDatabase/` (e.g. `insert_flows.py`, `insert_packets.py`, `insert_attacks_ipid.py`, `insert_attacks_window.py`, `insert_attacks_ack.py`)
  5. (optional) seed Mongo with `NoSQL/seed_vulnerabilities.py` and run `NoSQL/migrate_attacks_to_mongo.py`

Each script will read database connection details from the environment variables listed above. Review the scripts before running them (they were written for a controlled lab environment).

## Running the webapp (API + static UI)
1. Ensure the environment variables are set (see above)
2. Activate the virtualenv
3. Run the Flask app

   ```bash
   python webapp/app.py
   ```

The webapp will listen on the `PORT` (default 5003). Open a browser to http://localhost:5003 to view the static UI. The UI requires authentication (use `AUTH_USER` / `AUTH_PASS` configured above) before exposing controls.

## What the webapp exposes
- SQL endpoints (read-only):
  - `/api/summary` — overall counts (attacks / packets / flows) and Mongo counts
  - `/api/sql/latest-attacks` — recent attacks (accepts `?limit=`)
  - `/api/sql/attack-details` — attack + packet join (requires `?packet_id=`)
  - `/api/sql/attacks-by-field` — grouped or detailed attacks by modified field (`?field=&limit=`)
  - `/api/sql/flow-summary` — top flows (adapts to column names in your DB)
  - `/api/sql/packets-in-flow` — list packets in a flow (requires `?flow_id=`)
  - `/api/sql/ipid-distribution` — IPID counts for a flow (requires `?flow_id=`)
- Mongo endpoints:
  - `/api/mongo/vulnerabilities` — list seeded vulnerability docs
  - `/api/mongo/attacks-with-vuln` — aggregation join of attacks with vulnerabilities (accepts `?limit=`)

## Security and notes
- The webapp uses session-based login with credentials set via environment variables. This demo is not production hardened — do not expose it to untrusted networks without adding HTTPS, password hashing, and other hardening.
- The code attempts to adapt to minor schema variations (different column names) but you should inspect the SQL and table columns if you see errors like "Unknown column".
- The capture/send scripts are intended for lab/demo use only.

## Where to look next
- `webapp/app.py` — Flask server and API endpoints
- `webapp/static/index.html` — single-file demo UI
- `InsertDatabase/` — insert scripts for flows, packets and attacks
- `NoSQL/` — seed and migration scripts for Mongo
- `CapturePackets/` and `SendPackets/` — packet capture and send helpers

## Troubleshooting
- If you encounter SQL errors about unknown columns, check your MySQL schema and either rename columns or update the mapping logic in `webapp/app.py` to match your schema.
- If the UI returns authentication errors, make sure `AUTH_USER` and `AUTH_PASS` match what you provided.

If you would like, I can also add a `requirements.txt`, a `.env.example` or a small helper script to initialize the database schema — tell me which you prefer.
