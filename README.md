# GreatMigration

A web application and set of utilities for converting Cisco switch‐port configurations and safely pushing them to the Juniper Mist cloud.

The app provides:

* A FastAPI backend with endpoints for converting Cisco configs and applying port configuration through Mist’s REST API  
* A lightweight Tailwind‑based front‑end for uploading configs, mapping them to Mist switches, test‑running the results and (optionally) pushing live changes  
* Optional pluggable authentication (local username/password or LDAP/Active‑Directory)  
* Stand‑alone scripts for command‑line conversion and quick start automation

---

## Contents

* [Project Layout](#project-layout)  
* [Prerequisites](#prerequisites)  
* [Quick Start Script](#quick-start-script)  
* [Manual Setup](#manual-setup)  
* [Authentication](#authentication)  
* [Using the Web Interface](#using-the-web-interface)  
* [API Endpoints](#api-endpoints)  
* [Command‑Line Tools](#command-line-tools)  
* [Troubleshooting & Tips](#troubleshooting--tips)

---

## Project Layout

```
GreatMigration/
├─ backend/                 # FastAPI app and helpers
│  ├─ app.py                # Main API with conversion & push endpoints
│  ├─ auth_local.py         # Local username/password auth
│  ├─ auth_ldap.py          # LDAP/AD auth
│  ├─ convertciscotojson.py # Cisco→Mist JSON converter (CLI)
│  ├─ push_mist_port_config.py # Port‑config builder/pusher
│  └─ requirements.txt
├─ static/                  # Static assets served at /static
├─ templates/
│  └─ index.html            # Front‑end single‑page app
├─ quickstart.py            # Cross‑platform bootstrap script
└─ quickstart.ps1           # PowerShell variant
```

---

## Prerequisites

* **Python 3.9+**
* **pip**
* **Git** (for cloning the repository)
* A **Mist API token** with rights to read sites/devices and (for live pushes) modify switch configuration

---

## Quick Start Script

The fastest way to get running is with `quickstart.py`:

```bash
# Clone the repo, create a .venv, install dependencies, prompt for .env, and start the API
python quickstart.py --repo https://github.com/ejstover/GreatMigration.git --dir ./GreatMigration --branch main --port 8000
```

Subsequent runs (after the repo is cloned) only need the directory and port:

```bash
python quickstart.py --dir ./GreatMigration --port 8000
```

Use `--no-start` to perform setup without launching the server.  
The script creates/uses `backend/.env` to store your Mist token and optional defaults.

---

## Manual Setup

1. **Clone and enter the project**
   ```bash
   git clone https://github.com/ejstover/GreatMigration.git
   cd GreatMigration
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate      # Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r backend/requirements.txt
   ```

4. **Create `backend/.env`**
   ```ini
   # Required
   MIST_TOKEN=YOUR_MIST_API_TOKEN
   SESSION_SECRET=long_random_string              # used to sign session cookies

   # Optional defaults
   MIST_BASE_URL=https://api.ac2.mist.com         # adjust region if needed
   MIST_ORG_ID=                                   # default org for site picker
   AUTH_METHOD=local                              # or "ldap"; omit for no auth
   LOCAL_USERS=alice:pass1,bob:pass2              # for AUTH_METHOD=local
   LOCAL_PUSH_USERS=alice                         # who may push live changes
   # LDAP_* variables (see next section) for AUTH_METHOD=ldap
   ```

5. **Start the server**
   ```bash
   uvicorn app:app --app-dir backend --reload
   ```
   The API and front‑end will be available at <http://localhost:8000>.

---

## Authentication

Set `AUTH_METHOD` in the environment (`backend/.env`) to enable authentication.  
If `AUTH_METHOD` is omitted, the app runs without auth but warns on every request.

### Local Auth (`AUTH_METHOD=local`)

Environment variables:

* `LOCAL_USERS` – comma‑separated `user:pass` pairs  
* `LOCAL_PUSH_USERS` – comma‑separated usernames allowed to push live changes  
* `SESSION_SECRET` – required, used to sign session cookies

### LDAP/Active Directory (`AUTH_METHOD=ldap`)

Environment variables:

* `LDAP_SERVER_URL` – e.g. `ldaps://dc01.example.com:636`
* `LDAP_SEARCH_BASE` – e.g. `DC=example,DC=com`
* `LDAP_BIND_TEMPLATE` – e.g. `{username}@example.com` or `EXAMPLE\\{username}`
* `PUSH_GROUP_DN` – group whose members may push live changes (optional)
* `LDAP_SERVICE_DN` / `LDAP_SERVICE_PASSWORD` – service account for searches (optional)
* `SESSION_SECRET` – required

---

## Using the Web Interface

1. **Navigate to** `http://localhost:8000`  
   If auth is enabled you’ll be redirected to `/login`.

2. **Upload Cisco configuration files**  
   Drag & drop one or more config files onto the drop zone or click “Choose files”.

3. **Review converted JSON**  
   Each file is converted to normalized Mist port configuration JSON.  
   Click “Details” on a file to see the raw JSON.

4. **Map files to switches** (Batch Section)  
   For each converted file you must specify:
   * **Site** – fetched from Mist via `/api/sites`
   * **Device** – switch in the selected site (`/api/site_devices`)
   * Optional per‑row settings:
     - **Member offset** – shift FPC numbering if the Mist stack order differs
     - **Exclude ports** – comma‑separated Juniper interfaces to skip
     - **Model override** – force a specific EX4100 model
   Global options (top of batch section):
   * **Time zone** – used when tagging interface descriptions
   * **Model override** – default model if a row leaves it blank
   * **Test mode** (dry run) – send payload to Mist but do not apply changes
   * **Strict overflow** – drop interfaces that exceed inferred model capacity

5. **Test or Push**
   * With **Test mode** checked, the button reads “Test configuration for all”.
   * Uncheck **Test mode** and the button changes to “Push configuration for all”.
   * Results for each row (payload, validation, Mist response) appear below the batch table.

6. **Log out** via the “Log out” button in the header.

---

## API Endpoints

The front‑end is a thin layer over these REST endpoints (all JSON):

| Method | Path               | Description |
|-------|--------------------|-------------|
| GET   | `/api/sites`       | List sites accessible to the Mist token. Optional `org_id` query param. |
| GET   | `/api/site_devices`| List switch devices in a site (`site_id`). |
| POST  | `/api/convert`     | Upload Cisco config files; returns normalized JSON for each file. |
| POST  | `/api/push`        | Push (or dry‑run) a single JSON payload to a device. |
| POST  | `/api/push_batch`  | Push/dry‑run multiple rows in one request. |
| GET   | `/me`              | Current user info (requires auth). |
| GET   | `/login` / `/logout` | Auth endpoints (local or LDAP). |

All push endpoints require `MIST_TOKEN` to be present on the server and, when auth is enabled, the user must belong to the push‑allowed set/group.

---

## Command‑Line Tools

### `convertciscotojson.py`

Standalone converter for one file or a directory:

```bash
# Single file
python backend/convertciscotojson.py configs/Config.txt

# Bulk convert directory (outputs *_converted.json alongside originals)
python backend/convertciscotojson.py --bulk-convert configs/
```

Useful options:

```
--uplink-module 1          # Cisco module number used for uplinks (default 1)
--force-model ex4100-48mp  # Force all members to this model
--strict-overflow          # Error instead of guessing if port exceeds model capacity
```

### `push_mist_port_config.py`

Command‑line version of the port‑config builder/pusher.  
It accepts normalized JSON input and can test or apply to Mist switches.  
Refer to the in‑file comments for invocation patterns and rule customization.

---

## Troubleshooting & Tips

* **Authentication not configured** – ensure `AUTH_METHOD`, `SESSION_SECRET`, and the appropriate auth variables are set in the environment.
* **Missing Mist token** – `MIST_TOKEN` must be set before the server starts; otherwise `/api/*` endpoints return errors.
* **LDAP connection issues** – verify certificate trust when using `ldaps://` and confirm bind templates match your environment.
* **Dry runs** – always start with “Test mode” enabled to validate payloads and model capacity without touching live devices.
* **Member offsets** – use `member_offset` to handle switches whose Cisco member numbering differs from the target Mist stack order.
* **Strict overflow** – enable during conversion if you prefer to drop unmappable interfaces rather than guess their destinations.

---

This README text is provided as reference; you can place it in `README.md` in your repository and adjust any organization‑specific details as needed.

