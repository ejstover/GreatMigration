# GreatMigration

GreatMigration is an open‑source toolkit and web application that streamlines migrating Cisco switch‑port configurations into the Juniper Mist cloud. It parses legacy Cisco configs, translates them to Mist's JSON format, and provides both a browser interface and command‑line utilities to validate or deploy the resulting port settings.

Key features include:

* Guided web workflow for uploading configs, mapping to Mist sites/devices, and pushing updates
* Command‑line utilities for batch conversion and port configuration pushes
* Safe test mode for reviewing payloads before any live changes occur
* Adjusts for Cisco (1-based) and Juniper (0-based) port numbering so interface mappings remain accurate

## Screenshots

<!-- TODO: replace these placeholders with real screenshots -->
![Dashboard placeholder](docs/images/placeholder-dashboard.png)
![Upload interface placeholder](docs/images/placeholder-upload.png)
![Port mapping placeholder](docs/images/placeholder-port-mapping.png)
![Numbering difference placeholder](docs/images/placeholder-numbering.png)
![Rule builder placeholder](docs/images/placeholder-rules.png)
![CLI output placeholder](docs/images/placeholder-cli.png)

### Cisco vs. Juniper port numbering

Cisco switch interfaces are typically numbered starting at **1** (e.g., `FastEthernet0/1`), whereas Juniper uses **0** as the first index (e.g., `ge-0/0/0`). GreatMigration normalizes these differences during conversion so that, for example, a Cisco port 1 maps to the correct Juniper port 0. Keep this offset in mind when reviewing translated configurations.

### Cisco vs. Juniper port numbering

Cisco switch interfaces are typically numbered starting at **1** (e.g., `FastEthernet0/1`), whereas Juniper uses **0** as the first index (e.g., `ge-0/0/0`). GreatMigration normalizes these differences during conversion so that, for example, a Cisco port 1 maps to the correct Juniper port 0. Keep this offset in mind when reviewing translated configurations.

---

## Setup

### Prerequisites

* Python 3.9+
  * On Debian/Ubuntu systems ensure the `python3-venv` package is installed so virtual environments can be created.
* pip
* Git
* Mist API token with rights to read sites/devices and (optionally) modify switch configuration

### Quick start

```bash
# Clone the repo, create a .venv, install dependencies, prompt for .env, and start the API
python3 quickstart.py --repo https://github.com/ejstover/GreatMigration.git --dir ./GreatMigration --branch main
```

Subsequent runs (after the repo is cloned) only need the directory:

```bash
python3 quickstart.py --dir ./GreatMigration
```

On first run the script prompts for your Mist token and desired API port (default 8000). Use `--port` to override the stored value or `--no-start` to perform setup without launching the server. The script creates/uses `backend/.env` to store your Mist token and optional defaults.
It also copies `backend/port_rules.sample.json` to `backend/port_rules.json` so you can customize local rule mappings without committing them.

### Manual setup

1. **Clone and enter the project**
   ```bash
   git clone https://github.com/ejstover/GreatMigration.git
   cd GreatMigration
   ```
2. **Create a virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate      # Windows: .venv\\Scripts\\activate
   ```
   If you receive an error about `ensurepip` not being available, install the `python3-venv` package and retry.
3. **Install dependencies**
   ```bash
   pip install -r backend/requirements.txt
   ```
4. **Configure environment variables**
   Start from the sample file and populate the required fields:
   ```bash
   cp .env.sample backend/.env
   ```
   Edit `backend/.env` and set at minimum:
   ```ini
   MIST_TOKEN=your_mist_api_token
   SESSION_SECRET=long_random_string              # used to sign session cookies
   AUTH_METHOD=local                               # or "ldap"
   # Optional defaults such as MIST_BASE_URL, MIST_ORG_ID, SWITCH_TEMPLATE_ID, etc.
   ```
   The sample file contains additional settings for local or LDAP auth. Remove any lines you don't need.
5. **Initialize port rules (optional)**
   Start from the sample rules file so custom mappings stay out of version control:
   ```bash
   cp backend/port_rules.sample.json backend/port_rules.json
   ```
   Edit `backend/port_rules.json` as needed. The real file is listed in `.gitignore` so your rules remain local. Quickstart scripts perform this copy automatically.
6. **Start the server**
   ```bash
   uvicorn app:app --app-dir backend --reload
   ```
   The API and front-end will be available at <http://localhost:8000> (or the port you chose).

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
3. Review converted JSON and map each file to a Mist site and device. Changing the site on the first row cascades to all subsequent rows, but each row can still be adjusted individually.
4. Choose **Test mode** for a dry run or uncheck it to push live changes.
5. Optionally list interfaces to exclude. Provide each interface individually (e.g., `ge-0/0/1,ge-0/0/2`); range syntax is not supported yet.
6. Log out when finished.

### Test mode vs. live push

Both the web UI and CLI provide a dry‑run option so you can see exactly what would be sent to Mist before committing changes:

* **Test mode / `--dry-run`** – Builds the full payload, applies remaps and exclusions, and performs capacity validation without contacting the Mist API. The response includes the exact JSON that would be pushed along with any validation warnings.
* **Live push** – After successful validation, issues an HTTP `PUT` to the Mist device endpoint to apply the configuration. Live pushes are blocked if validation fails.

It is strongly recommended to run in test mode first, review the payload, and then perform a live push once satisfied.

### Rules interface

Access the rule builder at `http://localhost:8000/rules` to define how converted ports are mapped to Mist port profiles.

1. Click **Add Rule** to create a new entry and name it.
2. Under **If**, add one or more conditions (mode, VLANs, or a description regex).
3. Choose the desired Mist port profile in the **Then** column.
4. Drag the handle to reorder rules; earlier rules take precedence.
5. Click **Save** to persist your rules.


### Hardware replacement rules

Use the replacement rules editor at `http://localhost:8000/replacements` to map
Cisco hardware models to their Juniper counterparts. The page pulls available
models from the NetBox community device‑type library and saves your mappings to
`backend/replacement_rules.json`. Use the **Add New** option at the top of each
dropdown to enter custom hardware (such as SFPs) that isn't in the library.
Start from `backend/replacement_rules.sample.json` and customize as needed; the
real file is git‑ignored so local rules stay private.

These rules are also used by `translate_showtech.py` when converting `show
tech-support` inventories.


### Device Type Customization

By default, the app lists device types from the NetBox community library
referenced by the `NETBOX_DT_URL` environment variable. You can override this
URL if you maintain your own device type repository. You can also merge in your
own models by pointing the `NETBOX_LOCAL_DT` environment variable at a JSON
file. The file should map vendor names to a list of device type names:

```json
{
  "Cisco": ["CustomSwitch-1"],
  "Juniper": ["ex9999-48p"]
}
```

Any models defined here are appended to the community list for the matching
vendor. Duplicate names are ignored.

A starter file lives at `backend/custom_device_types.sample.json`; copy it to a
local path and set `NETBOX_LOCAL_DT` accordingly. Once configured, any models
added through the Hardware Replacement Rules page via the **Add New** option are
persisted to this file automatically, allowing custom entries to survive page
reloads.


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

Command-line version of the port-config builder/pusher. It accepts normalized JSON input and can test or apply to Mist switches. Use `--dry-run` to preview changes and `--exclude-interface` for each interface you want to skip; ranges such as `ge-0/0/1-3` are not supported. Refer to in-file comments for invocation patterns and rule customization.

**translate_showtech.py**

Parses a Cisco `show tech-support` text file to summarize hardware inventory and
suggest Juniper replacement models. The script looks for `PID` lines in the
`show inventory` section and maps them using `backend/device_map.json` (or the
sample file if local overrides are not present).  Any rules defined in
`backend/replacement_rules.json` are merged on top so they take precedence.

```bash
python backend/translate_showtech.py docs/samples/showtech_sample.txt
```

---

This README text is provided as reference; you can adjust any organization-specific details as needed.

