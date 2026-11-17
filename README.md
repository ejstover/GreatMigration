# GreatMigration

GreatMigration is a network automation toolkit designed to accelerate migrations to Juniper Mist.
It started as a switch conversion utility and now provides a full web application for:

- Discovering legacy Cisco hardware and recommending replacements.
- Converting Cisco switch configurations into Mist-compatible payloads.
- Applying standardized port profile rules at scale.
- Auditing Mist sites for compliance drift.
- Performing controlled, role-gated remediation actions.

If you are a network engineer using this for the first time, the most important thing to know is:
**GreatMigration is built around staged validation first, and automated changes second.**
Most workflows support non-destructive review before any push action is available.

---

## Table of contents
- [Feature overview](#feature-overview)
  - [Hardware conversion](#hardware-conversion)
  - [Port profile rules](#port-profile-rules)
  - [Standards](#standards)
  - [Config conversion](#config-conversion)
  - [Compliance audit & 1 Click Fix](#compliance-audit--1-click-fix)
- [Hamburger menu guide](#hamburger-menu-guide)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Quick start scripts](#quick-start-scripts)
  - [Manual setup](#manual-setup)
- [Extras: LDAP, syslog, and logging](#extras-ldap-syslog-and-logging)
- [Backend Python components](#backend-python-components-eli15)
- [Configuration reference](#configuration-reference)
- [Firewall requirements](#firewall-requirements)
- [Operational tips](#operational-tips)
- [Secure deployment and verification](#secure-deployment-and-verification)

---

## Feature overview

GreatMigration runs as a FastAPI web app with HTMX/Tailwind UI pages. Every operation is permission-aware:

- **Read-only users** can inspect data, run audits, and export results.
- **Push-enabled users** can execute change actions (Mist updates, 1 Click Fix, and push workflows).

Push rights are controlled through `PUSH_GROUP_DN` (LDAP mode) or `LOCAL_PUSH_USERS` (local auth mode).

### Hardware conversion

The Hardware Conversion workflow helps you answer: **“What Juniper hardware should replace this Cisco estate?”**

**What it does**

- Accepts Cisco `show tech-support` uploads.
- Or collects data over SSH directly from devices.
- Parses chassis, module, optics, and interface detail.
- Applies replacement mapping rules to suggest target Juniper models.
- Exports results as PDF/CSV for procurement and change documentation.

**How to use**

1. Open **Hardware Conversion**.
2. Choose input method:
   - **Upload bundle** for existing `show tech-support` files.
   - **SSH collect** to fetch inventory directly from switches.
3. Review parsed inventory and replacement suggestions.
4. Adjust mappings if needed (or update them in **Hardware Replacement Rules**).
5. Export reports for CAB/procurement review.

**How it works**

- Parsing and normalization are handled by `translate_showtech.parse_showtech`.
- Mapping is loaded through `translate_showtech.load_mapping` from `device_map.json` (or sample defaults).
- SSH collection is orchestrated by `backend/ssh_collect.py`, which runs command collection jobs and stores raw outputs for traceability.
- The same parser is used for upload and SSH sources, keeping results consistent regardless of intake method.

**Safety notes**

- Hardware conversion is an **analysis workflow** and does not push configuration to Mist.
- You can run this safely before any migration window.

### Port profile rules

Port Profile Rules provide deterministic logic for assigning Mist port usages from Cisco interface characteristics.

**What it does**

- Lets you define rule conditions such as mode, VLAN fields, PoE active status, and description regex.
- Uses ordered evaluation (first match wins).
- Stores rules in JSON for version control and reuse.
- Applies rules automatically during conversion and push preview.

**How to use**

1. Open **Rules → Port Profiles**.
2. Create or edit conditions (access/voice/native VLAN, trunk membership, description patterns).
3. Set the target Mist `usage` value.
4. Reorder rules to enforce priority.
5. Export/import JSON to standardize policy across teams.

**How it works**

- Rule files are validated via `push_mist_port_config.load_rules`.
- Interface matching uses `evaluate_rule` logic in conversion/push flows.
- The selected usage is injected into generated Mist `port_config` payloads.

**Safety notes**

- Rule updates do not change devices by themselves.
- You can validate rule effects through stage/test workflows before any live push.

### Standards

Standards gives you a live firmware baseline view so operators can see what versions should be targeted before migrations and audits.

**What it does**

- Displays a model-by-model firmware standards matrix for switches and APs.
- **Auto-Populates on Install**: On a new setup, the tool automatically fetches the latest suggested releases from the Mist API so your baseline is ready immediately.
- Shows multiple historical standards (Standard 1..N) so you can compare recency and baseline drift.
- Supports fast client-side filtering by model, device type, or version string.
- Exposes refresh timestamp metadata to confirm when the standards cache was last generated.

**How to use**

1. Open **Standards** from the menu.
2. Review **Standard 1** first (this is the primary baseline, including ZTP target for switches).
3. Use the filter box to find a specific model family or version.
4. Confirm required firmware expectations before running conversion push workflows or audit fixes.

**How it works**

- The Standards page (`/standards`) loads a table from `/api/standards`.
- The backend builds a normalized matrix from `standard_fw_versions.json`.
- **First-Run Behavior**: If `standard_fw_versions.json` is missing or empty, the backend automatically triggers a refresh from Mist to populate it.
- Firmware standards data is refreshed periodically (every 90 days by default) or can be manually triggered if the cache is stale.
- Push-enabled users can explicitly apply Standard 1 to the organization onboarding policy from the Standards page. Viewing or refreshing standards does not change Mist configuration.

**Safety notes**

- Standards is a **read-only reference workflow**.
- Viewing/filtering the table does not make any device changes.
- It is intended to be consulted before change workflows and during post-change validation.

### Config conversion

Config Conversion is the core migration path from Cisco CLI to Mist API payloads.

**What it does**

- Parses Cisco configs and builds Mist-ready `port_config` structures.
- Supports batch row-to-site/device mapping.
- Supports stack/chassis member remapping and uplink exclusion.
- Supports Stage/Test (preview) and Push (live Mist update).
- Includes lifecycle-oriented automation to move from temporary legacy layout toward final Juniper port state.

**How to use**

1. Open **Config Conversion**.
2. Upload one or more Cisco config files (or collect files over SSH).
3. Validate interface interpretation and member mapping.
4. Assign Mist org/site/device targets for each row.
5. Run **Stage/Test** first and review outputs.
6. Run **Push changes** only after review and approval.

**How it works**

- Parsing is performed by `convertciscotojson.convert_one_file` with CiscoConfParse.
- Payload construction merges conversion output, rule-driven usages, and selected Mist targets.
- Capacity/model guardrails are enforced via validation helpers in `push_mist_port_config.py`.
- Mist updates are executed through site/device API calls only when push workflows are explicitly triggered.

**Safety notes**

- Stage/Test is intended for pre-change validation and should be your default first step.
- Push controls are hidden/blocked for read-only users.
- Conversion output can be exported and peer-reviewed before any production change.

### Compliance audit & 1 Click Fix

Compliance Audit checks deployed Mist state against your operational standards.

**What it audits**

- Naming compliance (switches/APs).
- Required site variables.
- Template alignment and drift.
- Override cleanliness (including static DNS override cases).
- Device documentation/image coverage thresholds.

**Built-in 1 Click Fix actions**

- **AP naming remediation** based on LLDP neighbor context.
- **Switch static DNS cleanup** when template and variable prerequisites are met.

**How to use**

1. Open **Compliance Audit**.
2. Select org/site scope.
3. Run audit and inspect site cards/check summaries.
4. Export CSV summaries for records.
5. If authorized, run specific 1 Click Fix actions and monitor per-device status feedback.

**How it works**

- `compliance.py` builds site context from Mist API data and runs checks.
- `audit_history.py` stores run history for review/export.
- `audit_actions.py` defines available actions.
- `audit_fixes.py` executes each action with prerequisite checks and API operations.

**Configuration exceptions**

- Push-enabled users can select **Add to exceptions** beside a configuration deviation and record why that local variance is approved. Bundled differences can be approved one field at a time.
- Approvals are stored locally in `backend/exceptions.json` (ignored by Git), with the approved value, relevant standard, scope, reason, approver, and timestamp. Back up this file alongside your other local policy files.
- Each audit checks current Mist state first, then matches saved approvals. A changed value, relevant standard, organization, site, or device becomes actionable again. Display-name and unrelated telemetry changes do not invalidate an approval.
- **Approved exceptions** appear separately in the audit and its print/PDF export, excluded from actionable issue totals. Read-only users can view them.
- Open the **Exceptions** register before or after an audit to filter saved approvals by organization and selected sites. Push-enabled users can revoke them; revoked records remain available for traceability. Approvals have no expiry and can match again if their exact value and standard return, until revoked.
- Audit fixes recheck current approvals on the server, skipping protected targets or fields. Unavailable configuration or an unreadable exception store prevents affected fixes from proceeding safely. Saving or revoking an exception does not change Mist configuration.
- Exceptions cover configuration overrides, template alignment, naming, site variables, firmware, cloud management, spare-switch presence, and virtual-chassis roles. Health, service-level, and documentation findings remain actionable.
- A missing exception file means no approvals. A malformed or unreadable file is reported visibly and suppresses no findings; it is never silently replaced.

**Safety notes**

- Audit runs are passive by default. Push-enabled users may explicitly opt into active cable diagnostics.
- 1 Click Fix actions are explicit, per-action operations and remain permission-gated.
- Preconditions are checked before actions are enabled or executed.

---

## Hamburger menu guide

The hamburger menu (☰) is the main navigation pattern across pages (`/`, `/hardware`, `/replacements`, `/rules`, `/standards`, `/audit`).

### How the menu behaves

- Click ☰ to open/close.
- Click outside the drawer to close.
- Page content shifts when open so controls remain visible.
- Menu structure is consistent across feature pages.

### User/session behavior in the menu

- The UI calls `/me` and displays the current username.
- Read-only users are labeled as read-only where relevant.
- Log out is shown for active sessions and clears session state via `/logout`.
- Navigation visibility is broad, but mutating actions remain role-restricted.

### Menu items and what each one does

1. **Hardware Conversion** (`/hardware`)
   - Parse inventory and generate replacement recommendations.
2. **Hardware Replacement Rules** (`/replacements`)
   - Maintain Cisco→Juniper model mapping used by hardware conversion.
3. **Config Conversion** (`/`)
   - Convert configs and run stage/test/push workflows.
4. **Port Profile Rules** (`/rules`)
   - Define and prioritize interface-to-usage mapping logic.
5. **Standards** (`/standards`)
   - Review firmware standards by model/type and revision recency.
6. **Compliance Audit** (`/audit`)
   - Run compliance checks and optional 1 Click Fix remediations.
7. **Help** (`HELP_URL`)
   - Open your internal runbook/documentation target.

### Recommended operator workflow using the menu

1. **Standards**: verify software baseline expectations.
2. **Hardware Replacement Rules**: confirm model mapping policy.
3. **Hardware Conversion**: size migration hardware.
4. **Port Profile Rules**: validate interface policy translation.
5. **Config Conversion**: run stage/test and review payloads.
6. **Compliance Audit**: run post-stage checks, then apply fixes if needed.

This sequence minimizes risk by moving from policy/reference -> conversion planning -> controlled execution.

---

## Getting started

GreatMigration uses automation to simplify your first-run setup. Your local configuration files (like `.env`, `port_rules.json`, and `standard_fw_versions.json`) are **strictly local**. They are ignored by Git so that you can switch branches without losing your custom data or site settings.

### Prerequisites

- Git
- Python 3.11+ (`python3-venv` on Linux/macOS)
- Mist API token (read for discovery; write for push/fix workflows)
- Optional: PowerShell 5.1+ / 7.x for Windows quickstart

### Quick start scripts

These scripts handle cloning the repository, building the virtual environment, and initializing your local configuration files.

#### Python (cross-platform)

```bash
git clone -b main https://github.com/ejstover/GreatMigration.git ./GreatMigration
cd ./GreatMigration
python3 quickstart.py
```

**What it does:**

- **Sync Management**: Clones or updates the repo. If you have uncommitted changes on your current branch, it will skip updates to protect your work.
- **Environment Build**: Creates `.venv`, installs dependencies, and ensures `tmp_ssh_jobs/` and `logs/` directories exist.
- **Local Config Initialization**: Prompts for key settings to create `backend/.env` and automatically initializes `backend/port_rules.json` and `backend/standard_fw_versions.json` if they are missing.
- **Server Start**: Starts the API via `uvicorn` on port 8000 by default.

**Useful options:**

- `--repo`, `--dir`, `--branch`
- `--port`
- `--no-start`

#### PowerShell (Windows-friendly)

```powershell
Set-ExecutionPolicy -Scope Process RemoteSigned
./quickstart.ps1 -RepoUrl https://github.com/ejstover/GreatMigration.git -TargetDir C:\GreatMigration
```

**What it does:**

- Mirrors the Python quickstart behavior for Windows environments.
- Handles automated setup of local JSON config files and environment directories.
- Supports `-Branch`, `-Port`, and `-NoStart` switches.

### Manual setup

If you prefer to configure the tool manually:

1. **Clone + install dependencies**
   ```bash
   git clone https://github.com/ejstover/GreatMigration.git
   cd GreatMigration
   python3 -m venv .venv
   source .venv/bin/activate  # Windows: .\.venv\Scripts\activate
   pip install -r backend/requirements.txt
   ```

2. **Create `backend/.env`**
   The application relies on this file for all core settings. You can copy `.env.sample` to get started.

   **Required Core Values:**
   - `MIST_TOKEN`: Your API token (requires write access for push/fix actions).
   - `SESSION_SECRET`: A long random string for session security.
   - `AUTH_METHOD`: Set to `local` or `ldap`.

   **Common Configuration:**
   - `MIST_BASE_URL`: Default is `https://api.ac2.mist.com`.
   - `MIST_ORG_ID`: Preset your Organization ID for faster workflows.
   - `SWITCH_TEMPLATE_ID`: The Mist Switch Template to align against.
   - `API_PORT`: Default is `8000`.
   - `HELP_URL`: Link to your internal runbook or documentation.

   **Local Auth Settings (`AUTH_METHOD=local`):**
   - `LOCAL_USERS_FILE`: Hash-only account database, normally `data/local_users.json`.
   - Run `python backend/security_setup.py --add-user USERNAME --push` to create a push-enabled account; omit `--push` for read-only access.

   **LDAP Settings (`AUTH_METHOD=ldap`):**
   - `LDAP_SERVER_URL`: Your validating `ldaps://` directory server.
   - `LDAP_SERVICE_DN` and `LDAP_SERVICE_PASSWORD`: Required for session authorization checks.
   - `LDAP_CA_CERTS_FILE`: Optional corporate CA bundle.
   - `LDAP_SEARCH_BASE`: Root DN for searches.
   - `PUSH_GROUP_DN`: Members of this group can perform "Push" actions.

3. **Initialize Local Configuration**
   Run `python backend/security_setup.py` to generate a secure signing key and migrate legacy local credentials.

   The application requires these files to be present in the `backend/` directory:
   - `port_rules.json`: Define your interface-to-usage mapping (see `port_rules.sample.json`).
   - `standard_fw_versions.json`: Stores your firmware baseline (initialized automatically on first run).
   - `device_map.json`: Optional custom hardware mappings (see `device_map.sample.json`).

4. **Run the app**
   ```bash
   uvicorn app:app --host 127.0.0.1 --port 8000 --app-dir backend
   ```

### First-run checklist

1. For loopback-only HTTP development, set `SESSION_HTTPS_ONLY=false` and open `http://localhost:8000`. Shared deployments require HTTPS and an explicit `APP_ALLOWED_HOSTS` setting.
2. Confirm authentication works with your chosen auth method.
3. Validate read-only user behavior first.
4. Run non-destructive workflows (hardware parse, stage/test, compliance audit).
5. Execute push/fix operations only after review and approval.

---

## Extras: LDAP, syslog, and logging

- **LDAP auth (optional)**
  - Set `AUTH_METHOD=ldap` and directory settings.
  - Group-based role control separates read-only and push users.

- **Syslog forwarding (optional)**
  - Set `SYSLOG_HOST` and `SYSLOG_PORT`.
  - If syslog is unavailable, local logging continues.

- **Local audit logging (default)**
  - Action logs are written under `backend/logs/` for operational traceability.

---

## Backend Python components

- `backend/app.py`: FastAPI server, endpoints, session/auth checks, and orchestration.
- `backend/convertciscotojson.py`: Cisco config parser and Mist payload builder.
- `backend/push_mist_port_config.py`: Rule evaluation, payload validation, and push helpers.
- `backend/translate_showtech.py`: Show-tech parsing and hardware mapping helpers.
- `backend/ssh_collect.py`: Multi-device SSH intake pipeline.
- `backend/compliance.py`: Compliance check framework and site-level runners.
- `backend/audit_actions.py`: Catalog of available remediation actions.
- `backend/audit_fixes.py`: Execution logic for remediation actions.
- `backend/audit_history.py`: Persistence and retrieval for audit history.
- `backend/auth_local.py`: Local auth logic.
- `backend/auth_ldap.py`: LDAP auth and group resolution.
- `backend/logging_utils.py`: File/syslog user action logging.

---

## Configuration reference

### Authentication and roles

- `AUTH_METHOD=local` uses the scrypt-hashed account database in `LOCAL_USERS_FILE`. Legacy plaintext entries are migrated by the setup utility.
- `AUTH_METHOD=ldap` uses LDAP bind/search plus group DNs.
- Push rights come from `PUSH_GROUP_DN` (LDAP) or each local account's `can_push` field.
- Shared deployments require HTTPS; keep `SESSION_HTTPS_ONLY=true`. See [secure deployment and verification](#secure-deployment-and-verification) for certificate, SSH trust, retention, migration, and test instructions.

### Mist connectivity

- `MIST_BASE_URL` defaults to the AC2 Mist API domain.
- `MIST_TOKEN` is required for Mist API access.
- `MIST_ORG_ID` can be preset for faster operator workflows.

### Compliance policy tuning

- Naming patterns: `SWITCH_NAME_REGEX_PATTERN`, `AP_NAME_REGEX_PATTERN`.
- Required variables: `MIST_SITE_VARIABLES` (`key=value` entries).
- Documentation minimums: `SW_NUM_IMG`, `AP_NUM_IMG`.
- Standards cache/source behavior uses `backend/standard_fw_versions.json` with periodic refresh.

### VLAN/reserved behavior for conversion safety

- `LEGACY_VLANS` identifies VLANs preserved in legacy/staged workflows.
- `EXCLUDE_VLANS` omits specific VLANs from generated outputs.
- `RESERVED_VLANS` protects reserved IDs with explicit naming (format `id:name`).

### 1 Click Fix safeguards

- AP rename actions depend on LLDP-derived context and skip when required data is missing.
- DNS cleanup actions validate template and site-variable prerequisites before enabling execution.

---

## Firewall requirements

Allow these flows in controlled environments:

| Direction | Protocol/Port | Destination | Purpose |
|-----------|---------------|-------------|---------|
| Inbound   | TCP `API_PORT` (default 8000) | Admin/operator workstations | Access the web UI. |
| Outbound  | TCP 443 | Mist API endpoint (`api.ac2.mist.com` or regional host) | Read inventory, run audits/fixes, and perform pushes. |
| Outbound  | TCP 443 | `api.github.com` and optional `NETBOX_DT_URL` | Pull device type metadata used in conversion workflows. |
| Outbound  | TCP 22 | Managed switches | SSH collection and SSH-driven network workflows. |
| Outbound | TCP 636 (or configured LDAPS port) | LDAP/AD servers | Required only when using LDAP auth. |

LDAP requires LDAPS with a trusted certificate; unencrypted LDAP is rejected.

---

## Operational tips

- **Start read-only**: validate inventory, rules, and audits before allowing push access.
- **Use stage/test first**: treat push as a final approved step, not the first step.
- **Back up local policy securely**: keep `port_rules.json`, `device_map.json`, and related mappings in a private configuration store, outside this public repository.
- **Review logs after every change window**: local logs and Mist audit logs should agree.
- **Re-run quickstart periodically**: this updates dependencies and keeps local setup aligned.

GreatMigration is designed to reduce migration risk by making change intent visible, reviewable, and role-controlled.

## Secure deployment and verification

### Installation and account migration

Run `python backend/security_setup.py` before starting an existing installation.
Quick-start runs this automatically. Setup replaces weak session signing keys,
migrates legacy local accounts to `backend/data/local_users.json` with salted
scrypt password hashes, removes plaintext account entries from `.env`, and scrubs
legacy HTTP payload logs. It preserves the Mist token and unrelated settings.
Existing sessions require a new login.

Use `python backend/security_setup.py --add-user USERNAME --push` to create or
update a push-enabled account; omit `--push` for read-only access. Passwords are
entered through a hidden prompt. Use `--revoke-sessions` to revoke all sessions.
Local account or role edits take effect on the next request; LDAP sessions
revalidate directory access on every request. Sessions expire after one hour.

### Hosting, credentials, and trusted connections

- Keep access restricted to trusted operators on a management network. All
  authenticated users share installation evidence and the configured Mist service
  account. Use separate installations when those users must be isolated.
- Quick-start binds to loopback. For shared hosting, configure `APP_ALLOWED_HOSTS`
  with exact public hostnames, terminate HTTPS at a trusted reverse proxy, and keep
  `SESSION_HTTPS_ONLY=true`. Configure Uvicorn to trust forwarded headers only from
  that proxy. Loopback HTTP development requires `SESSION_HTTPS_ONLY=false`.
- `MIST_BASE_URL` selects the region; `MIST_ALLOWED_HOSTS` adds exact approved API
  hostnames. Requests with the Mist token require an approved HTTPS API origin and
  certificate verification; credentialed redirects are disabled.
- LDAP requires `ldaps://`, a trusted certificate (optionally configured through
  `LDAP_CA_CERTS_FILE`), and a service account for session authorization checks.
  Directory validation failures deny access.
- SSH requires verified keys in the normal known-hosts file or
  `SSH_KNOWN_HOSTS_FILE`. Verify fingerprints through a trusted channel before
  adding keys; do not disable host-key checks.
- Restrict `.env`, local account databases, sessions, evidence, logs, and backups
  to the service account and administrators, including Windows filesystem ACLs.
  Use a Mist token scoped to the operations and organizations the installation
  needs. Never commit live credentials or customer configurations.

### Evidence retention and resource limits

Defaults are 16 MiB per request, 16 uploads, eight in-flight requests per process,
two shared SSH jobs, eight workers per SSH job, one-hour temporary SSH retention,
and 30-day saved evidence retention. `MAX_REQUEST_BYTES`, `MAX_INFLIGHT_REQUESTS`,
`MAX_SSH_JOBS`, and `NETWORK_DATA_RETENTION_DAYS` configure the corresponding limits.
Background maintenance removes expired evidence and orphaned SSH captures.
Retention excludes local accounts, sessions, and audit exceptions; retain secure
backups of policy files and approved exceptions separately. These limits do not
replace reverse-proxy connection limits or host disk monitoring.

### Development verification

Install tools with `python -m pip install -r backend/requirements-dev.txt`, then
`python -m playwright install chromium`. Run:

```text
python -m pytest backend -q
python -m ruff check backend quickstart.py tests --select E9,F63,F7,F82
python -m pip_audit -r backend/requirements.txt
python -m pip_audit -r backend/requirements-dev.txt
python -m pip check
npm ci --ignore-scripts
npm run build:css
git diff --exit-code -- static/app.css
npm audit
```

The suite uses synthetic infrastructure and isolated storage, including browser
and SSH transport tests. Automated tests must never use production credentials or
make production network changes. Windows and Linux CI run these checks.

Runtime frontend assets are committed so Node is needed only for development.
After changing templates, rebuild CSS as above. When updating Sortable, copy
`Sortable.min.js` and its license from the pinned `node_modules/sortablejs`
package's `Sortable.min.js` and `LICENSE` into `static/vendor/`. Verify both files
match the package before committing. Keep dependency changes, lockfiles, and
generated assets together in the same pull request.

Pull requests also run dependency review and redacted secret scanning. Weekly
audits and Dependabot updates help detect newly disclosed vulnerabilities; they
do not certify the application as vulnerability-free. See [SECURITY.md](SECURITY.md)
for supported versions and private vulnerability reporting.
