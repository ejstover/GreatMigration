# GreatMigration

A web application and set of utilities for converting Cisco switch-port configurations and safely pushing them to the Juniper Mist cloud.

---

## Setup

### Prerequisites

* Python 3.9+
* pip
* Git
* Mist API token with rights to read sites/devices and (optionally) modify switch configuration

### Quick start

```bash
# Clone the repo, create a .venv, install dependencies, prompt for .env, and start the API
python quickstart.py --repo https://github.com/ejstover/GreatMigration.git --dir ./GreatMigration --branch main --port 8000
```

Subsequent runs (after the repo is cloned) only need the directory and port:

```bash
python quickstart.py --dir ./GreatMigration --port 8000
```

Use `--no-start` to perform setup without launching the server. The script creates/uses `backend/.env` to store your Mist token and optional defaults.

### Manual setup

1. **Clone and enter the project**
   ```bash
   git clone https://github.com/ejstover/GreatMigration.git
   cd GreatMigration
   ```
2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate      # Windows: .venv\\Scripts\\activate
   ```
3. **Install dependencies**
   ```bash
   pip install -r backend/requirements.txt
   ```
4. **Create `backend/.env`**
   ```ini
   MIST_TOKEN=YOUR_MIST_API_TOKEN
   SESSION_SECRET=long_random_string              # used to sign session cookies
   # Optional defaults such as MIST_BASE_URL, MIST_ORG_ID, AUTH_METHOD, etc.
   ```
5. **Start the server**
   ```bash
   uvicorn app:app --app-dir backend --reload
   ```
   The API and front-end will be available at <http://localhost:8000>.

---

## Components

* **backend/** – FastAPI application with conversion and push endpoints. Supports optional local or LDAP/AD authentication.
* **templates/** – Front-end templates including the rule builder at `/rules`.
* **static/** – Tailwind-based assets used by the front-end.
* **quickstart.py / quickstart.ps1** – Scripts that bootstrap the project.
* **backend/convertciscotojson.py** – Command-line Cisco→Mist JSON converter.
* **backend/push_mist_port_config.py** – Command-line port-config builder/pusher.

---

## Usage

### Web interface

1. Navigate to `http://localhost:8000` (login if authentication is enabled).
2. Upload Cisco configuration files.
3. Review converted JSON and map each file to a Mist site and device.
4. Choose **Test mode** for a dry run or uncheck it to push live changes.
5. Log out when finished.

### Rules interface

Access the rule builder at `http://localhost:8000/rules` to define how converted ports are mapped to Mist port profiles.

1. Click **Add Rule** to create a new entry and name it.
2. Under **If**, add one or more conditions (mode, VLANs, or a description regex).
3. Choose the desired Mist port profile in the **Then** column.
4. Drag the handle to reorder rules; earlier rules take precedence.
5. Click **Save** to persist your rules.


### Command-line tools

**convertciscotojson.py**

```bash
# Single file
python backend/convertciscotojson.py configs/Config.txt

# Bulk convert directory (outputs *_converted.json alongside originals)
python backend/convertciscotojson.py --bulk-convert configs/
```

Useful options:

```
--uplink-module 1
--force-model ex4100-48mp
--strict-overflow
```

**push_mist_port_config.py**

Command-line version of the port-config builder/pusher. It accepts normalized JSON input and can test or apply to Mist switches. Refer to in-file comments for invocation patterns and rule customization.

---

This README text is provided as reference; you can adjust any organization-specific details as needed.

