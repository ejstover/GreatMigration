# GreatMigration

GreatMigration is a network automation toolkit designed to accelerate moves to Juniper Mist. The project grew from the Mist Switch Configuration Converter but now delivers a cohesive web application that helps engineers normalize legacy device data, validate Mist deployments, and remediate issues with a single click.

---

## Table of contents
- [Feature overview](#feature-overview)
  - [Hardware conversion](#hardware-conversion)
  - [Port profile rules](#port-profile-rules)
  - [Config conversion](#config-conversion)
  - [Compliance audit & 1 Click Fix](#compliance-audit--1-click-fix)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Quick start scripts](#quick-start-scripts)
  - [Manual setup](#manual-setup)
- [Configuration reference](#configuration-reference)
- [Firewall requirements](#firewall-requirements)
- [Operational tips](#operational-tips)

---

## Feature overview

GreatMigration ships with a responsive FastAPI + HTMX interface backed by a Mist-aware automation engine. All features honour Mist RBAC by granting “push” capabilities only to users in `PUSH_GROUP_DN` (or local users flagged via `LOCAL_PUSH_USERS`). Read-only users can still explore reports, download data, and stage conversion payloads.

### Hardware conversion

* Collect Cisco hardware details either by uploading `show tech-support` bundles **or** by letting the app log in over SSH.
* Receive Juniper (or custom) replacement suggestions based on curated mappings.
* Export a PDF summary for procurement or change records.

**How to use**

1. Navigate to **Hardware Conversion** in the web UI.
2. Choose one of the collection methods:
   * **Upload bundle** – drag-and-drop a `show tech-support` archive (or browse to select one).
   * **SSH collect** – provide the device IP/hostname plus credentials and start a job; the worker logs in and executes
     `show inventory`, `show interface status`, `show interfaces`, and `show running-config`, then persists the raw text for auditing.
3. Review the parsed chassis, line cards, and optics that appear in the results grid.
4. Adjust suggested replacements if needed, then download the PDF report or CSV export for planning.

**How it works**

* Uploads and SSH jobs both flow through `translate_showtech.parse_showtech`, which normalizes Cisco hardware tables and drives
  the recommendation engine (`translate_showtech.load_mapping`, `find_copper_10g_ports`).
* SSH collection is orchestrated by `backend/ssh_collect.py`: a thread pool launches Netmiko sessions per device, runs the
  command set above, captures stdout to disk, and synthesizes a `show tech` bundle so the same parser can be reused.
* Replacement suggestions are computed from `backend/device_map.sample.json` (or your customized `device_map.json`) and surfaced
  alongside interface counts so you can spot copper-to-fiber mismatches before ordering hardware.

### Port profile rules

* Maintain reusable mappings between detected Cisco interface traits and Mist port profiles.
* Build rules with multiple conditions (mode, description regex, VLANs, etc.) using a drag-and-drop priority list.
* Persist rule sets in `backend/port_rules.json` so they can be version-controlled or shared.

**How to use**

1. Open **Rules → Port Profiles** to see the existing rule stack.
2. Click **Add rule** to describe the Cisco traits (mode, access VLAN, voice VLAN, native VLAN, description regex, etc.).
3. Choose the Mist port usage that should be applied when a port matches the conditions.
4. Reorder rules to set priority—first match wins during conversions.
5. Use **Export JSON** to capture the current rule file or **Import JSON** to load a curated set into `backend/port_rules.json`.

**How it works**

* Rules are stored in JSON and validated/loaded through `push_mist_port_config.load_rules` so malformed entries are rejected early.
* During conversions the backend evaluates interfaces against each rule (`evaluate_rule`) using traits such as mode, access/voice
  VLANs, native VLAN, allowed VLAN membership, and description/name regex matches; the first rule that returns `True` supplies
  the target `usage`.
* The matched usage is injected into the generated Mist `port_config` payloads before staging or pushing so rule tweaks immediately
  impact both dry runs and live updates.

### Config conversion

* Translate legacy switch configs into Mist-ready JSON payloads.
* Batch map converted payloads to Mist sites and devices, tweak chassis member offsets, exclude uplinks, and override device models.
* Stage configurations or push live updates using the Site Deployment Automation controls; push options require push rights.

**How to use**

1. Visit **Config Conversion** and upload one or more Cisco configuration files (raw CLI or archive).
2. Inspect the parsed inventory and optionally adjust offsets/exclusions so the converted members align with target hardware.
3. Select the destination Mist org/site/device for each row. The UI displays the generated Mist payload preview.
4. Use the **Site Deployment Automation** section:
   * Choose **Stage/Test** to download the Mist payload or perform a dry run without changing devices.
   * Choose **Push changes** to send the converted configuration to Mist (requires push permissions).
5. Download the JSON or CSV exports for documentation or manual review at any stage.

**How it works**

* File uploads flow through `convertciscotojson.convert_one_file`, which relies on `CiscoConfParse` to model every interface, infer
  EX4100 member types, and translate Cisco naming into Mist FPC/port identifiers while preserving VLAN, PoE, QoS, and description
  details.
* Batch pushes reuse `_build_payload_for_row` inside `backend/app.py` to merge the converted `port_config` with Mist site/device
  selections, apply rule-driven port usages, enforce capacity checks (`validate_port_config_against_model`), and PUT the results to
  `/sites/{site_id}/devices/{device_id}`.
* Lifecycle Management (LCM) automation reuses the same converted payloads for Step 3 after staging temporary VLANs/port profiles
  in earlier steps, ensuring the final Juniper configuration exactly matches the Cisco source minus deprecated interfaces.

### Compliance audit & 1 Click Fix

* Audit one or more Mist sites for required variables, device naming conventions, template adherence, documentation completeness, and configuration overrides.
* Drill into site cards to see affected devices, override diffs, and remediation suggestions.
* Take advantage of the following built-in 1 Click Fix actions (visible to push-enabled users):
  * **Access point naming:** rename Mist APs to match the required pattern using LLDP neighbour data. Buttons appear per device so you can remediate selectively.
  * **Switch static DNS cleanup:** remove statically configured management DNS servers from `ip_config` while respecting lab vs. production template assignments. Pre-checks verify the expected template and DNS site variables; buttons stay disabled and display guidance until prerequisites are met.
* UI status badges show live Mist API feedback next to each button so operators immediately see success, skipped states, or pre-check failures.

**How to use**

1. Open **Compliance Audit** and pick the Mist org and sites you want to evaluate.
2. Click **Run audit** to fetch live Mist data and generate the compliance report.
3. Expand each site card to review checks, affected devices, and recommended fixes.
4. For push-enabled users, click the appropriate **1 Click Fix** buttons (e.g., AP rename, DNS cleanup). Each button re-validates prerequisites before issuing Mist API calls.
5. Download the audit summary or device-level CSV exports for change records or further analysis.

**How it works**

* The audit engine (`backend/compliance.py`) hydrates a `SiteContext` with data from Mist site, derived setting, template, and device
  APIs, then runs a library of `ComplianceCheck` subclasses to flag naming violations, missing variables, override drift, and
  documentation gaps.
* Findings are serialized through `audit_history` so the UI can show site/device counts and let you export CSV snapshots for change
  control.
* 1 Click Fix actions map to helpers in `audit_fixes.py`/`audit_actions.py`; each button re-checks prerequisites, stages a dry run
  when requested, and otherwise issues Mist REST calls (e.g., rename APs, clear DNS overrides) while streaming per-device status
  back to the browser.

---

## Getting started

### Prerequisites

* Git
* Python 3.9+ with `python3-venv` (Linux/macOS) or the Windows Store/official installer
* Mist API token with read access (for lookups) and write access (optional, required for pushes and 1 Click Fix actions)
* Optional: PowerShell 5.1+ or PowerShell 7.x if you prefer the Windows script

### Quick start scripts

Two scripts provide identical setup behaviour so teams can use whichever platform is most convenient.

#### Python (cross-platform)

```bash
git clone -b main https://github.com/ejstover/GreatMigration.git ./GreatMigration
cd ./GreatMigration
python3 quickstart.py
```

* Updates or clones the repository, builds `.venv`, installs backend dependencies, prompts for Mist credentials, creates `backend/.env`, ensures `backend/port_rules.json`, and starts `uvicorn`.
* Re-run later with `python3 quickstart.py` to reuse cached settings.
* Supply `--repo`, `--dir`, and `--branch` to bootstrap alternative locations; `--port` overrides the API port; `--no-start` performs setup without launching the API.

#### PowerShell (Windows-friendly)

```powershell
# From a PowerShell prompt
Set-ExecutionPolicy -Scope Process RemoteSigned
./quickstart.ps1 -RepoUrl https://github.com/ejstover/GreatMigration.git -TargetDir C:\GreatMigration
```

* Mirrors the Python script: syncs the git repo, provisions `.venv`, installs requirements (bootstrapping `pip` if necessary), builds `backend/.env`, ensures `backend/port_rules.json`, and starts the API.
* Supports `-Branch`, `-Port`, and `-NoStart` switches for parity with `quickstart.py`.

Both scripts read and reuse values in `backend/.env`, so follow-up runs only prompt when settings are missing.

### Manual setup

1. **Clone and prepare the project**
   ```bash
   git clone https://github.com/ejstover/GreatMigration.git
   cd GreatMigration
   python3 -m venv .venv
   source .venv/bin/activate  # .\.venv\Scripts\activate on Windows
   pip install -r backend/requirements.txt
   ```
2. **Configure the backend**
   * Copy `.env.sample` to `backend/.env` and populate:
     * `MIST_TOKEN`
     * `SESSION_SECRET`
     * `AUTH_METHOD` (`local` or `ldap`)
     * For local auth: `LOCAL_USERS` and optional `LOCAL_PUSH_USERS`
     * For LDAP auth: `LDAP_SERVER_URL`, `LDAP_SEARCH_BASE`/`LDAP_SEARCH_BASES`, `LDAP_BIND_TEMPLATE`, `LDAP_SERVICE_DN`, `LDAP_SERVICE_PASSWORD`, plus `PUSH_GROUP_DN` and optional `READONLY_GROUP_DN`
     * Optional defaults: `MIST_BASE_URL`, `MIST_ORG_ID`, `SWITCH_TEMPLATE_ID`, `API_PORT`, `HELP_URL`
     * Compliance tuning: `SWITCH_NAME_REGEX_PATTERN`, `AP_NAME_REGEX_PATTERN`, `MIST_SITE_VARIABLES`, `SW_NUM_IMG`, `AP_NUM_IMG`
     * Device catalog sources: `NETBOX_DT_URL`, `NETBOX_LOCAL_DT`
     * Logging: `SYSLOG_HOST`, `SYSLOG_PORT`
3. **Optional assets** – copy `backend/port_rules.sample.json` to `backend/port_rules.json` to maintain custom mappings outside version control.
4. **Launch the API**
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --app-dir backend --reload
   ```

---

## Configuration reference

* **Authentication & authorization**
  * `AUTH_METHOD=local` uses users listed in `LOCAL_USERS` (`username:password`). Include comma-separated pairs and flag push-enabled accounts in `LOCAL_PUSH_USERS`.
  * `AUTH_METHOD=ldap` supports read-only (`READONLY_GROUP_DN`) and push-enabled (`PUSH_GROUP_DN`) directory groups. Multiple values can be separated by semicolons or newlines.
* **Mist connectivity**
  * `MIST_BASE_URL` defaults to `https://api.ac2.mist.com`. Change it if your org lives in another Mist region.
  * `MIST_ORG_ID`, `SWITCH_TEMPLATE_ID`, and `API_PORT` can be pre-filled to streamline onboarding.
* **Compliance checks**
  * Override naming patterns via `SWITCH_NAME_REGEX_PATTERN` / `AP_NAME_REGEX_PATTERN`.
  * Adjust required site variables with `MIST_SITE_VARIABLES`.
  * Enforce device documentation photo counts with `SW_NUM_IMG` and `AP_NUM_IMG`.
* **1 Click Fix safeguards**
  * AP rename actions derive new names from switch LLDP neighbours. Sites lacking neighbour data will surface actionable warnings but skip changes.
  * Switch DNS cleanup actions verify the applied template (`Prod - Standard Template` for production sites, `Lab` template for lab sites) and the presence of `siteDNSserver`, `hubDNSserver1`, and `hubDNSserver2`. Buttons remain disabled until both checks pass and are annotated with details describing any failures.

---

## Firewall requirements

Allow the following flows if your environment restricts outbound traffic:

| Direction | Protocol/Port | Destination | Purpose |
|-----------|---------------|-------------|---------|
| Inbound   | TCP `API_PORT` (8000 by default) | Admin workstations | Reach the GreatMigration web UI. Adjust if `API_PORT` is changed. |
| Outbound  | TCP 443 | `api.ac2.mist.com` (or your regional Mist API host) | Fetch inventory, perform 1 Click Fix actions, push configurations. |
| Outbound  | TCP 443 | `api.github.com` (and any custom `NETBOX_DT_URL`) | Download device type metadata referenced during conversions. |
| Outbound  | TCP 22  | Managed switches | Allow the automation engine to initiate SSH sessions when executing configuration pushes or validation steps. |
| Outbound† | TCP 389 / 636 | LDAP / Active Directory servers | Needed only when `AUTH_METHOD=ldap`. |

†Use the secure port declared in `LDAP_SERVER_URL` (e.g., 636 for LDAPS).

---

## Operational tips

* **Role-based controls** – buttons that modify Mist (push, 1 Click Fix) only appear for users in the push group. Read-only users can still download reports and review findings.
* **Dry runs first** – compliance actions report their intended changes before applying them, and the Site Deployment automation flow offers a dedicated Stage/Test option for safe validation.
* **Troubleshooting** – review `backend/logs/app.log` (when syslog forwarding is not configured) and inspect Mist audit logs for confirmation of pushed changes.
* **Staying current** – re-run either quick start script periodically; both update the git checkout, dependencies, and `.env` defaults while preserving custom settings.

Enjoy building faster Juniper Mist migrations!
