# GreatMigration

## Overview

GreatMigration is a suite network automation tools to help teams move quickly to Juniper Mist. It was inspired by [Switch Configuration Converter](https://github.com/Mist-Automation-Programmability/mist_switch_converter). The major difference being this project creates a JSON paylod to configure indvidual ports vs. creating a template per switch. It works well for teams that are focused on deploying a single switch template. Currently the suite include hardware conversion and configuration conversion. Both tools are rule based conversion utilites that evaluate inputs and produce outputs that teams can use manually or push via the API. 

## Setup

### Prerequisites

* Python 3.9+
* `python3-venv` package (Linux) for virtual environments
* Git and pip
* Mist API token with rights to read (to populate drop downs) and modify (optional, only necessary if you push changes) switches

### Quick start

```bash
python3 quickstart.py --repo https://github.com/ejstover/GreatMigration.git --dir ./GreatMigration --branch main
```

Subsequent runs only need the directory:

```bash
python3 quickstart.py --dir ./GreatMigration
```

The script prompts for a Mist token and API port, stores them in `backend/.env`, installs dependencies, and launches the API.  Use `--no-start` to perform setup without starting the server.

### Manual setup

1. Clone the repo and create a virtual environment
2. `pip install -r backend/requirements.txt`
3. Copy `.env.sample` to `backend/.env` and populate at minimum:
   * `MIST_TOKEN` – Mist API token
   * `SESSION_SECRET` – random string for signing session cookies
   * `AUTH_METHOD` – `local` (default) or `ldap`
   * For **local** auth: set `LOCAL_USERS` with comma‑separated `user:pass` pairs and optional `LOCAL_PUSH_USERS` for accounts allowed to push to Mist
   * For **LDAP** auth: uncomment `AUTH_METHOD=ldap` and configure `LDAP_SERVER_URL`, `LDAP_SEARCH_BASE`, `LDAP_BIND_TEMPLATE`, `PUSH_GROUP_DN`, `LDAP_SERVICE_DN`, and `LDAP_SERVICE_PASSWORD`
   * Optional defaults: `MIST_BASE_URL`, `MIST_ORG_ID`, `SWITCH_TEMPLATE_ID`, `HELP_URL`
   * Device type sources: `NETBOX_DT_URL` (community library) and `NETBOX_LOCAL_DT` for additional models
4. (Optional) copy `backend/port_rules.sample.json` to `backend/port_rules.json` to maintain custom port mappings outside version control
5. Start the server with `uvicorn app:app --app-dir backend --reload`

### Firewall rules

If the host running GreatMigration sits behind a restrictive firewall, allow the
following flows so the application and its dependencies can reach external
services:

| Direction | Protocol/Port | Destination | Purpose |
|-----------|---------------|-------------|---------|
| Inbound   | TCP `API_PORT` (8000 by default) | Admin workstation network | Reach the FastAPI UI. Adjust the port if you change `API_PORT` in `backend/.env`. |
| Outbound  | TCP 443 | `api.ac2.mist.com` (or your regional Mist API endpoint) | Interact with the Mist cloud. |
| Outbound  | TCP 443 | `api.github.com` (or custom NetBox device type source) | Download device type definitions referenced by `NETBOX_DT_URL`. |
| Outbound† | TCP 389 / 636 | Your LDAP/Active Directory servers | Required only when `AUTH_METHOD=ldap`. |

†Use the secure port specified in `LDAP_SERVER_URL` (e.g., 636 for LDAPS).

## Hardware Conversion

This page parses Cisco `show tech-support` files and lists user specified Juniper or other OEM replacement models. 

1. **File area** – drag text files into the drop zone or click **Choose files** to open the hidden file selector.
2. **Clear** – removes all uploaded results.
3. **Download PDF** – appears after processing and exports a report of detected hardware.

Each processed file shows the detected Cisco items and their suggested replacements.

## Hardware Replacement Rules

Create permanent mappings between Cisco and Juniper model names.

* **Add Rule** – inserts a new row in the table.
* **Cisco Model** / **Juniper Model** – drop-downs for each side.  Use **Add New** within a select to open a modal with a text box where custom models can be entered.
* **Delete (✕)** – removes a rule.
* **Save** – writes the rules to `backend/replacement_rules.json`.
* **Cancel** – leaves without saving.

## Config Conversion

Convert Cisco configs, map them to Mist switches, and test or push the resulting port settings.

1. **File area** – drop configs or click **Choose files** to start conversion.  Use **Clear** to reset.
2. **Converted JSON Preview** – shows the normalized output for each file.
3. **Batch: Map files to switches** – adds a row per file with the following controls:
   * **Site** – drop-down listing Mist sites.
   * **Device** – drop-down listing switches within the selected site.
   * **Start member** – number box offsetting Juniper virtual-chassis member numbers.
   * **Start port** – number box shifting port numbering within a member.
   * **Exclude uplinks** – checkbox that skips common uplink interfaces.
   * **Exclude interfaces** – text box for comma-separated interface names or ranges to skip.
   * **Remove row (✕)** – deletes the mapping row.
4. **Global options** above the table:
   * **Time zone** – read‑only text box displaying the zone used when pushing.
   * **Model override** – text box applied to rows without their own model override.
   * **Test mode (no changes)** – checkbox that sends payloads without applying them.
   * **Strict overflow (convert)** – checkbox that drops unmappable interfaces during conversion.
5. **Test configuration for all / Apply configuration for all** – button that runs a dry run or pushes live based on **Test mode**.

Results include per‑row payloads, validation warnings, and (for live pushes) the Mist API response.

## Port Profile Rules

Define how converted interfaces map to Mist port profiles. First match wins.

* **Add Rule** – appends a new rule.
* **Name** – text box naming the rule.
* **If** column – each rule can have multiple conditions: select a field (mode, VLANs, description regex, etc.) and enter a value in the accompanying text box.  Use **+ condition** to add more or **✕** to remove one.
* **Then** column – drop‑down selecting the Mist port profile to apply when conditions match.
* **Drag handle** – reorder rules; earlier rules take precedence.
* **Save** – persists the rule set.
* **Cancel** – returns to the main page without saving.


