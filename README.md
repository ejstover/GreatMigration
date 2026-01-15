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

* Upload Cisco `show tech-support` bundles to identify hardware that needs replacement.
* Receive Juniper (or custom) replacement suggestions based on curated mappings.
* Export a PDF summary for procurement or change records.

### Port profile rules

* Maintain reusable mappings between detected Cisco interface traits and Mist port profiles.
* Build rules with multiple conditions (mode, description regex, VLANs, etc.) using a drag-and-drop priority list.
* Persist rule sets in `backend/port_rules.json` so they can be version-controlled or shared.

### Config conversion

* Translate legacy switch configs into Mist-ready JSON payloads.
* Batch map converted payloads to Mist sites and devices, tweak chassis member offsets, exclude uplinks, and override device models.
* Test configurations (dry-run) or push live updates when “Test mode” is disabled and the signed-in user has push rights.

### Compliance audit & 1 Click Fix

* Audit one or more Mist sites for required variables, device naming conventions, template adherence, documentation completeness, and configuration overrides.
* Drill into site cards to see affected devices, override diffs, and remediation suggestions.
* Take advantage of the following built-in 1 Click Fix actions (visible to push-enabled users):
  * **Access point naming:** rename Mist APs to match the required pattern using LLDP neighbour data. Buttons appear per device so you can remediate selectively.
  * **Switch static DNS cleanup:** remove statically configured management DNS servers from `ip_config` while respecting lab vs. production template assignments. Pre-checks verify the expected template and DNS site variables; buttons stay disabled and display guidance until prerequisites are met.
* UI status badges show live Mist API feedback next to each button so operators immediately see success, skipped states, or pre-check failures.

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
    * Compliance tuning: edit `backend/compliance_rules.json` (or the Compliance Rules page)
     * Device catalog sources: `NETBOX_DT_URL`, `NETBOX_LOCAL_DT`
     * Logging: `SYSLOG_HOST`, `SYSLOG_PORT`
     * Compliance rule builder API sources: `PLATFORM_API_SOURCES` or per-platform `*_API_SPEC`
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
  * Use the Compliance Rules page (or edit `backend/compliance_rules.json`) to override naming patterns, required site variables, firmware lists, and documentation photo counts.
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
* **Dry runs first** – compliance actions report their intended changes before applying them, and the config conversion module offers a “Test mode” toggle for safe validation.
* **Troubleshooting** – review `backend/logs/app.log` (when syslog forwarding is not configured) and inspect Mist audit logs for confirmation of pushed changes.
* **Staying current** – re-run either quick start script periodically; both update the git checkout, dependencies, and `.env` defaults while preserving custom settings.

Enjoy building faster Juniper Mist migrations!
