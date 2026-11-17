# GreatMigration

GreatMigration is a FastAPI web application for network engineers migrating Cisco switches to Juniper Mist. It recommends replacement hardware, translates switch configurations, previews and applies migration payloads, compares pre/post-migration MAC placement, and audits Mist sites with permission-gated remediation.

**Preview proposed changes before applying them.** Read-only accounts can inspect inventory, convert configurations, collect SSH evidence, save conversion sets, compare snapshots, and run passive audits. Push-enabled accounts can also change shared policy, update Mist configuration, approve/revoke audit exceptions, and explicitly request active cable diagnostics. Application permissions and the Mist token's permissions must both permit a live action.

Authenticated users share this installation's evidence and Mist service account. Deploy on a restricted management network; use separate installations when operators or organizations need isolation.

## Table of contents

- [Prerequisites and setup](#prerequisites-and-setup)
- [Configuration reference](#configuration-reference)
- [Operator workflows](#operator-workflows)
- [Secure deployment and verification](#secure-deployment-and-verification)
- [Operations and maintenance](#operations-and-maintenance)
- [Troubleshooting](#troubleshooting)
- [Development verification](#development-verification)
- [Project components](#project-components)

## Prerequisites and setup

- Git and Python with `venv`/`pip`. CI verifies Python **3.11** on Windows and Linux; use that version for a reproducible starting point. Newer Python versions and macOS are not covered by that CI matrix.
- On Debian/Ubuntu, install `python3-venv` if environment creation reports that `ensurepip` is unavailable.
- A Mist API token for the required region and organizations. Read access supports discovery/audits; live pushes and fixes need corresponding write permissions.
- For SSH: network reachability, Cisco IOS credentials with access to collection commands, and verified SSH host keys.
- Node is needed only to develop/rebuild frontend assets. CSS and Sortable assets are committed for normal installations.

Run commands from the repository root unless specified otherwise. Keep actual credentials, network configurations, evidence, and backups private.

### Manual setup on Windows

Use PowerShell. These examples invoke the virtual environment's Python directly, so activation is optional.

```powershell
git clone https://github.com/ejstover/GreatMigration.git
Set-Location GreatMigration
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
Copy-Item .env.sample backend/.env
```

Edit `backend/.env`: replace `MIST_TOKEN`, confirm `MIST_BASE_URL`, and keep `AUTH_METHOD=local` for this example. For **loopback-only HTTP**, change `SESSION_HTTPS_ONLY=false`. Leave it `true` for shared HTTPS deployments.

```powershell
.\.venv\Scripts\python.exe backend/security_setup.py
.\.venv\Scripts\python.exe backend/security_setup.py --add-user operator
.\.venv\Scripts\python.exe -m uvicorn app:app --app-dir backend --env-file backend/.env --host 127.0.0.1 --port 8000
```

The first command generates a random session signing key. The second prompts twice for a password of at least 12 characters and creates a read-only account. Add `--push` when creating/updating an account that should apply changes.

### Manual setup on Linux

```bash
git clone https://github.com/ejstover/GreatMigration.git
cd GreatMigration
python3.11 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
cp .env.sample backend/.env
```

Edit `backend/.env` as described above, including `SESSION_HTTPS_ONLY=false` for loopback-only HTTP. Then run:

```bash
.venv/bin/python backend/security_setup.py
.venv/bin/python backend/security_setup.py --add-user operator
.venv/bin/python -m uvicorn app:app --app-dir backend --env-file backend/.env --host 127.0.0.1 --port 8000
```

Use `python3` instead of `python3.11` only after confirming the selected version. Activation is optional: `source .venv/bin/activate` on Linux or `.\.venv\Scripts\Activate.ps1` on Windows, followed by `python` commands.

### First sign-in

1. Open `http://localhost:8000` for the loopback HTTP examples and sign in as `operator`.
2. Confirm read-only access. Verify Mist region/organization by loading sites or Standards.
3. Convert a synthetic/sample Cisco configuration and use **Stage/Test converted config** before processing a migration.
4. Review site policy and firmware selection before granting push access. The sample lists required variable names without deployment-specific default values.
5. Before SSH collection, verify device fingerprints through a trusted channel and add the verified keys to the service account's known-hosts file or `SSH_KNOWN_HOSTS_FILE`.

### Quickstart scripts

Normal quickstart starts the installed app **without fetching code, installing packages, or running setup**. Use Python on Windows, Linux, or macOS, or the PowerShell wrapper on Windows:

```text
python quickstart.py                         # start the installed app
python quickstart.py setup                   # first installation or setup repair
python quickstart.py setup --no-start        # configure without launching
python quickstart.py upgrade                 # explicit fast-forward upgrade
python quickstart.py upgrade --no-start      # upgrade without restarting
python quickstart.py status
python quickstart.py stop
python quickstart.py restart
python quickstart.py autostart enable
python quickstart.py autostart disable
python quickstart.py autostart status
```

Use `py -3.11` on Windows or `python3.11` on Linux/macOS when needed. PowerShell uses the same command names: `.\quickstart.ps1 setup -NoStart`, `.\quickstart.ps1 upgrade`, and `.\quickstart.ps1 autostart enable`. Keep both root launchers together. The wrapper prefers the target's existing virtual-environment interpreter.

Setup creates/repairs `.venv`, installs requirements, prompts for missing `backend/.env`, runs security migration, initializes missing local rules/cache/directories, and retains existing settings/accounts/data. Stop the app before setup; maintenance commands cannot overlap. **The initial quickstart local account remains push-enabled.** Use manual setup for an initial read-only account. Setup can clone a missing target, but never fetches or updates an existing installation. Noninteractive setup requires a configured environment file and accounts; it never waits for setup answers. For a new checkout:

```text
python quickstart.py setup --repo https://github.com/ejstover/GreatMigration.git --dir /path/to/GreatMigration --no-start
```

| Python option | PowerShell equivalent | Behavior |
| --- | --- | --- |
| `--dir PATH` | `-TargetDir PATH` | Target installation; default current directory. |
| `--repo URL` | `-RepoUrl URL` | Source override for explicit setup/upgrade only. |
| `--branch NAME` | `-Branch NAME` | Branch override for explicit setup/upgrade only. |
| `--port NUMBER` | `-Port NUMBER` | Foreground launch override; otherwise `API_PORT` or `8000`. |
| `--no-start` | `-NoStart` | Suppress setup launch or upgrade restart. Alone, remains an alias for `setup --no-start`. |
| `setup --autostart` | `setup -Autostart` | Enable boot startup without the setup yes/no question. |
| `setup --no-autostart` | `setup -NoAutostart` | Disable boot startup and stop the managed instance. |

#### Start automatically after reboot

Interactive setup asks **Start GreatMigration automatically when this computer boots? [y/N]**. The default is no; an existing registration is preserved unless explicitly changed. Enable/disable it later with the `autostart` commands. Enabling registers startup without immediately launching; `start` launches now. Disabling stops the managed instance and removes its registration.

Windows uses a startup scheduled task; Linux requires a running systemd service manager; macOS uses a LaunchDaemon. Services run under the installing user's account, before sign-in, with absolute interpreter/checkout paths and a fixed project-root working directory. Only OS registration/control uses administrator privileges. Windows registration prompts for the **Windows account password**, not the application password or Windows Hello PIN; account policy must permit batch logon. Its password is handled by the native credential prompt/Task Scheduler, never saved in application files or arguments. Linux/macOS use `sudo` for registration/control. Unsupported environments retain foreground startup.

Once registered, normal `start` uses the service and returns its URL/log location. Otherwise it stays in the foreground; Ctrl+C stops it. `stop`/`restart` control only the installed service. Services and foreground launches honor `APP_HOST`, load environment settings before application imports, use one worker, and prevent duplicate quickstart instances. Managed launches use `API_PORT`; edit the file and restart rather than supplying a conflicting one-time `--port`.

Use a stable local installation directory accessible to the service account. Moving a checkout changes its service identifier: disable startup before moving, then enable it at the new location. Avoid a login-mounted/encrypted-only location for pre-sign-in hosting. Service startup output is appended to `backend/logs/quickstart-service.log`; OS service-manager logs can also explain registration/bootstrap errors. Restart attempts have delays and limits; inspect logs and run `start` after correcting a repeated failure. Rotate/archive service logs as part of normal maintenance.

Firmware setup only creates an empty cache; Standards/audit workflows populate it. For LDAP, use setup-only mode, replace directory/group placeholders, and review CA settings before launch. Reboot service installation is covered by mocked definition/lifecycle tests; native boot smoke tests are a separate release check described in [quickstart validation](docs/quickstart-validation.md).

## Configuration reference

Copy the root [.env.sample](.env.sample) to **`backend/.env`**. The app loads it, then performs a fallback dotenv search; existing process variables take precedence. Quickstart launchers instead export file values into the child process, overriding inherited values. Avoid competing root/backend `.env` files.

Restart after environment changes. The documented Uvicorn `--env-file backend/.env` loads settings before module initialization, including syslog. Most policy paths are fixed under `backend/`; exceptions are noted below. Prefer absolute paths for external files.

### Core settings and local authentication

| Setting | Default / requirement | Purpose and format |
| --- | --- | --- |
| `AUTH_METHOD` | Required: `local` or `ldap` | Missing/other values leave authenticated workflows unavailable. |
| `SESSION_SECRET` | Required, random, at least 32 characters | Generate with `security_setup.py`; no usable built-in key. |
| `SESSION_HTTPS_ONLY` | `true` | Secure cookies and HTTPS enforcement. Set exactly `false` only for HTTP with both host and client on loopback. |
| `APP_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Comma-separated exact hostnames/IPs without scheme/port; set public names for shared hosting. |
| `API_PORT` | Quickstart fallback `8000` | Quickstart only. Direct Uvicorn starts require `--port`. |
| `APP_HOST` | Quickstart fallback `127.0.0.1` | Bind address for both launchers and installed services; direct Uvicorn uses `--host`. |
| `QUICKSTART_REPO_URL` | `https://github.com/ejstover/GreatMigration.git` | Source for explicit clone/upgrade; set to your fork as needed. |
| `QUICKSTART_BRANCH` | `main` | Branch for explicit clone/upgrade. |
| `MIST_TOKEN` | Required for Mist workflows | Server-side token; account permissions do not grant token privileges. |
| `MIST_BASE_URL` | `https://api.ac2.mist.com` | Regional HTTPS API origin; optional `/api/v1` suffix is normalized. |
| `MIST_ALLOWED_HOSTS` | Empty | Additional exact approved API hostnames, comma-separated; configured Mist host and AC2 are already allowed. |
| `MIST_ORG_ID` | Empty | Default organization; some workflows discover organizations if absent. Configure explicitly for organization-policy synchronization. |
| `SWITCH_TEMPLATE_ID` | Empty | Network template used to obtain switch port profiles. |
| `HELP_URL` | Sample points to this repository's README | Set explicitly: the unset code fallback still points to the older `jacob-hopkins` repository. |
| `LOCAL_USERS_FILE` | Sample `data/local_users.json`; unset code fallback: legacy entries | JSON account database; relative to `backend/`. Must exist before local-auth startup when configured. |
| `LOCAL_USERS`, `LOCAL_PUSH_USERS` | Empty; legacy migration only | Old inline account/role settings. Use the setup utility and hash-only database for new installs. |

With an active virtual environment, create/update accounts using:

```text
python backend/security_setup.py --add-user observer
python backend/security_setup.py --add-user operator --push
python backend/security_setup.py --revoke-sessions
```

Omitting `--push` when updating an account makes it read-only. Passwords use hidden prompts, require at least 12 characters, and are stored as salted scrypt hashes. Local password/role edits invalidate affected sessions on the next authenticated request. Sessions last one hour. Revocation clears all installation sessions, including LDAP sessions.

### LDAP configuration

Use `AUTH_METHOD=ldap`, replace the commented examples in `.env.sample`, and leave only the intended authentication selection active.

| Setting | Default / requirement | Purpose and format |
| --- | --- | --- |
| `LDAP_SERVER_URL` | Required deployment value; code fallback is a sample server | `ldaps://hostname:636` or configured LDAPS port; plain LDAP is rejected. |
| `LDAP_SEARCH_BASE` | Required deployment value; code fallback `DC=testdomain,DC=local` | Base DN for user searches. |
| `LDAP_SEARCH_BASES` | Falls back to `LDAP_SEARCH_BASE` | Bases separated by semicolons/newlines; DN components keep their commas. |
| `LDAP_BIND_TEMPLATE` | `{username}@testdomain.local` | User-bind format; set for your directory. |
| `LDAP_SERVICE_DN` | Required deployment value; code fallback is a sample DN | Service account for directory/session authorization. |
| `LDAP_SERVICE_PASSWORD` | Required | Service-account password. |
| `PUSH_GROUP_DN` | Empty | One group DN granting push access; without it, LDAP users cannot push. |
| `READONLY_GROUP_DN` | Empty | Allowed read-only groups, separated by semicolons/newlines. |
| `LDAP_MATCHING_RULE_IN_CHAIN` | `true` | Enables recursive directory membership lookup, with implementation fallback checks. |
| `LDAP_CA_CERTS_FILE` | Unset; platform trust | Optional trusted CA bundle; prefer an absolute path. |

When either group setting is configured, users must belong to an allowed push/read-only group to sign in. Push-group membership grants push access even with read-only membership. With neither group configured, authenticated directory users receive read-only access. Sessions revalidate account/group access through the service account on each authenticated request; directory validation failures deny access.

### Migration and compliance policy

| Setting | Default | Purpose and format |
| --- | --- | --- |
| `LEGACY_VLANS` | Built-in `10,500-599` | Comma-separated IDs/ranges **added to** the built-in set for lifecycle preservation/prefix policy. Cannot remove built-in IDs. |
| `EXCLUDE_VLANS` | Empty | IDs/ranges excluded from the `legacy_` naming prefix during temporary network/profile generation; does **not** remove VLANs from conversion output. |
| `RESERVED_VLANS` | `1:vlan1` | Additional/overridden reserved names, comma-separated `id:name` pairs. |
| `SWITCH_NAME_REGEX_PATTERN` | Built-in region/site/location/role convention | Blank or invalid override falls back to `DEFAULT_SWITCH_NAME_PATTERN` in [compliance.py](backend/compliance.py). |
| `AP_NAME_REGEX_PATTERN` | Built-in region/site/location/AP-number convention | Regex override; see `DEFAULT_AP_NAME_PATTERN` in [compliance.py](backend/compliance.py). Audit patterns do not rewrite remediation's naming algorithm. |
| `MIST_SITE_VARIABLES` | `hubradiusserver,localradiusserver,siteDNS,hubDNSserver1,hubDNSserver2` | Comma-separated required keys. Optional `key=value` entries supply approved missing-variable fix defaults. Bare keys have no fix default. |
| `SW_NUM_IMG`, `AP_NUM_IMG` | `2` each | Minimum documentation images per switch/AP; non-negative integers (`0` permits none). |
| `TZ` | `America/New_York` | IANA zone for audit/report timestamps; conversion also exposes a time-zone field. |
| `NETBOX_DT_URL` | GitHub contents API for `netbox-community/devicetype-library/device-types` | Library root for vendor model lists. Physical-port discovery also uses built-in GitHub Juniper metadata URLs. |
| `NETBOX_LOCAL_DT` | Empty | Vendor-to-model-list JSON; see [custom_device_types.sample.json](backend/custom_device_types.sample.json). Required for custom-model saves. Relative to working directory; create its parent first. Supplements online lookup, not an offline port-layout database. |

Firmware policy comes from `backend/standard_fw_versions.json`. `STD_SW_VER` and `STD_AP_VER` are not consumed by the implementation and are no longer in the sample.

### Logging, storage, and resource settings

| Setting | Default | Purpose and format |
| --- | --- | --- |
| `SYSLOG_HOST` | Empty (disabled) | UDP syslog destination. Legacy `SYSLOG_SERVER` is used only when `SYSLOG_HOST` is empty/unset. |
| `SYSLOG_PORT` | `514` | UDP destination port; local logging remains enabled. |
| `SSH_KNOWN_HOSTS_FILE` | Unset | Additional verified known-hosts file; normal service-account keys also load. Prefer an absolute path. |
| `SECURITY_DB_PATH` | `backend/data/security.sqlite3` | SQLite sessions, rate limits, SSH leases. Relative overrides use the working directory; prefer an absolute path. |
| `MAX_REQUEST_BYTES` | `16777216` (16 MiB) | Overall body limit for state-changing requests; login has a fixed 8 KiB limit. |
| `MAX_INFLIGHT_REQUESTS` | `8` | Concurrent requests per process. |
| `MAX_SSH_JOBS` | `2` | Shared job limit across workers using the same security database. |
| `NETWORK_DATA_RETENTION_DAYS` | `30` | Conversion-set/snapshot retention by file modification age; minimum effective value one day. |

Use positive integers for resource limits. Upload endpoints permit up to 16 files; SSH requests permit up to eight workers per job. These limits do not replace proxy connection limits or disk monitoring.

### Local policy files and precedence

Local policy, evidence, and credentials are ignored by Git. Versioned samples are starting points; sample updates do not overwrite existing local files.

| File under `backend/` | Loading / writing behavior |
| --- | --- |
| `port_rules.local.json` → `port_rules.json` → `port_rules.sample.json` | UI reads the first existing file. Conversion loader tries this order, falling through read/parse errors. **Port Profile Rules saves `port_rules.local.json`**; a valid local file overrides primary rules. Ordered rules use first match wins. |
| `device_map.json` or `device_map.sample.json` | Local base Cisco PID-to-Juniper map wins over sample. |
| `replacement_rules.json` or `replacement_rules.sample.json` | Overlays the base hardware map; local file wins. **Hardware Replacement Rules saves `replacement_rules.json`**, including accessories. |
| `standard_fw_versions.json` | Firmware cache; created empty by quickstart or populated by workflow refresh. No manual copy required. |
| `exceptions.json` | Audit approvals, written through the UI with locking. Missing means no approvals; malformed/unreadable data produces an error and suppresses no findings. |

Manual setup can use sample port/hardware rules directly; these local JSON files are not all mandatory. UI policy edits require push rights but do not themselves change a device. Restart after direct file edits to refresh cached rules/settings; UI port-rule saves refresh the saving process's rules.

## Operator workflows

The menu shows the current user and logout. Server-side permissions apply even when a page is visible to all accounts.

| Page | Route | Purpose |
| --- | --- | --- |
| Hardware Conversion | `/hardware` | Upload/collect inventory; review replacements and export PDF/CSV. |
| Hardware Replacement Rules | `/replacements` | Hardware mapping overrides/accessories. |
| Config Conversion | `/` | Parse, map, preview, deploy, save conversion sets. |
| Network Snapshot | `/network-snapshot` | Legacy MAC baseline and post-cutover Mist placement comparison. |
| Port Profile Rules | `/rules` | Ordered interface-to-usage rules. |
| Standards | `/standards` | Firmware baselines and explicit onboarding-policy synchronization. |
| Compliance Audit | `/audit` | Checks, history, exceptions, exports, eligible fixes. |
| Help | `HELP_URL` | Configured runbook/documentation. |

### Hardware and port-rule preparation

1. Review replacement mappings/accessories in **Hardware Replacement Rules**.
2. In **Hardware Conversion**, upload Cisco `show tech-support` files or collect over SSH. Collection combines individual show-command outputs for the same parser used by uploads.
3. Review chassis/modules, active optics, copper 10G exceptions, and recommended replacements. Resolve unmapped items and export for procurement/change review. This workflow does not push Mist configuration.
4. Review **Port Profile Rules** before conversion. Conditions include mode, data/voice/native VLANs, trunk membership, PoE, description/interface patterns, and catch-all rules. Set target Mist `usage`, order priorities, and import/export JSON. Validate effects in a conversion preview.

### Config conversion and lifecycle automation

1. Upload Cisco configurations or use SSH collection; review converted JSON.
2. Assign each row's Mist site/device and model. Check stack member/start-port offsets, module normalization, uplink exclusions, and explicit interface exclusions. Repeated devices need distinct member/port offsets; inspect overlap/capacity diagnostics.
3. Select one phase per run and inspect every row's payload, warnings, failures, and results. A successful HTTP response does not mean every row succeeded.

| Automation selection | Effect |
| --- | --- |
| Site Deployment: **Stage/Test converted config** | Build/validate device payloads; no configuration write. Mist read calls may still be required. |
| Site Deployment: **Push converted config** | Apply device configuration through Mist; needs push rights and write-capable token. |
| LCM Step 1: **Review the temporary Cisco layout** | Preview temporary VLANs, profiles, and switchport payloads; no configuration write. |
| LCM Step 2: **Push the temporary Cisco layout** | Apply temporary legacy layout to Juniper switches through Mist. |
| LCM Step 3: **Deploy the final Juniper config** | Select cleanup site/switches. First UI run previews; after successful preview, **Apply Configuration** performs cleanup and derived final port assignments. Review site/template profiles and preserved usages first. |

Site Deployment and Lifecycle actions are separate choices; do not combine phases. Step 3 uses selected cleanup targets and live Mist site/template/device state, without requiring re-uploaded Cisco rows. Default preservation includes VLAN `10` and `500-599`, configured additions, and **Additional VLANs to preserve** entered for the run. This changes site-level settings as well as selected switches; inspect the full preview.

Before cutover, enter a project name and save the mapped conversion set using **Snapshot Prep**. It freezes input/mapping information and labels for Network Snapshot; saving does not deploy configuration. This local evidence is subject to retention, so back it up for longer change records.

### Network Snapshot

1. Save a mapped conversion set from Config Conversion before migration.
2. Open **Network Snapshot**, enter the same project name, select the intended saved set, and review the frozen Cisco-to-Juniper mapping. The latest set is auto-selected for a project's first baseline when available; a single available set can also be auto-selected.
3. Supply legacy devices and SSH credentials; choose **Capture pre-migration baseline**. Device labels/hostnames must align with saved source configurations. Collection includes MAC, ARP, neighbor, VLAN, interface, and running-configuration evidence; it does not configure switches.
4. Keep the page open until collection finishes and confirms baseline saving. After cutover, select that baseline and choose **Compare current Mist state to baseline**. Without selection, the latest baseline is used.
5. Review reconciliation and project history. Comparison reads Mist state and saves local evidence without changing Mist configuration.

| Reconciliation status | Interpretation |
| --- | --- |
| `matched_expected_port` | Expected site, switch, and port. |
| `matched_expected_switch_wrong_port` | Expected switch, different port. |
| `matched_same_site_wrong_switch` | Expected site, different switch. |
| `matched_elsewhere` | No expected target matches; also investigate missing source-to-target mappings. |
| `ambiguous_multiple_locations` | Multiple current observations for that MAC. |
| `missing_in_current_mist_state` | Baseline MAC absent from collected Mist observations. |
| `new_post_only_mac` | Post-cutover MAC absent from baseline. |

Comparison checks observed MAC location, not end-to-end service health or VLAN equivalence. Endpoint activity, collection completeness, telemetry, and mapping quality affect results; investigate missing/ambiguous records alongside service validation. Names normalize into filesystem keys: use distinct stable project names that remain distinct after spaces/punctuation normalize.

### Standards

Viewing Standards or running a firmware audit checks `standard_fw_versions.json`; missing/empty data or a cache at least **90 days** old triggers a refresh attempt. There is no independent 90-day scheduler or guaranteed install-time fetch. With no eligible returned versions, the cache can remain empty/unchanged.

Current selection keeps switch releases tagged **`junos_suggested`** and AP releases whose **`tag` is `alpha`**. Review AP selection against your approved firmware policy before relying on it. The page filters cached models to configured/discovered organization inventory, displaying up to six version columns and refresh metadata. Standard 1 is the first cached version per model.

Viewing/filtering/refreshing changes no Mist configuration. Push-enabled users can explicitly synchronize Standard 1 from this page to switch auto-upgrade custom versions in organization onboarding policy. Confirm `MIST_ORG_ID` and the baseline first; synchronization is a live organization-level change.

### Compliance Audit and 1 Click Fix

Select sites or **Entire Org**, run the audit, inspect summaries/history, and export CSV or print/PDF records. Checks cover site variables, switch-template alignment, configuration overrides, site SLEs, firmware, cloud management, power-supply health, spare-switch presence, virtual-chassis roles, naming, and documentation images.

Audits are passive by default. Active cable diagnostics require explicit opt-in and push permission; they issue device diagnostics and should be scheduled appropriately.

| Available fix | Prerequisites / effect |
| --- | --- |
| AP naming | Derives names from LLDP switch context and built-in naming logic; skips missing/invalid context and naming conflicts. |
| Switch static DNS cleanup | Clears eligible overrides only when approved-template and site-DNS-variable prerequisites hold. |
| Enable cloud management | Enables management on selected eligible switches. |
| Set site variables | Fills missing/unset variables from approved `MIST_SITE_VARIABLES` defaults; retains populated values. Bare keys cannot be filled automatically. |
| Set spare switch role | Needs a suitable switch without active physical client connections and a derivable spare name; updates role/name. |
| Set virtual-chassis roles | Needs target VC identifier and a supported, determinable layout; updates preprovisioned member roles. |

Availability depends on findings/prerequisites. Live fixes need push rights and appropriate token permissions; handlers recheck current data. Review per-target updated/skipped/failed feedback and rerun the audit. Not every finding has a fix.

**Approved exceptions:** Push-enabled users choose **Add to exceptions**, supply a reason, and approve individual fields in bundled differences. Approvals record scope, value, relevant standard, reason, approver, and timestamp in `backend/exceptions.json`. Current state is checked first: changed values, standards, organizations, sites, or devices become actionable again; unrelated telemetry/display-name changes do not invalidate approvals.

Approvals appear separately in audit/print/PDF output, excluded from actionable totals. The **Exceptions** register filters by organization/sites; push-enabled users revoke approvals while retaining revoked records for traceability. Approvals do not expire and can match again if exact value/standard returns, until revoked. They cover overrides, template alignment, naming, variables, firmware, cloud management, spare presence, and VC roles. Health, SLE, and documentation findings remain actionable.

Saving/revoking changes local policy only. Fixes recheck approvals and skip protected targets/fields; unreadable approvals or unavailable configuration block affected fixes. Preserve malformed stores and restore/repair verified records rather than deleting policy to silence an error.

## Secure deployment and verification

Use a restricted service account and management network. Restrict `.env`, accounts, evidence, logs, SQLite state, known-hosts files, and backups to service/admin accounts, including Windows ACLs. Scope the Mist token to needed organizations/operations. See [SECURITY.md](SECURITY.md) for supported versions and confidential reporting.

For shared hosting, terminate HTTPS at a trusted reverse proxy, retain `SESSION_HTTPS_ONLY=true`, set exact public `APP_ALLOWED_HOSTS`, and restrict backend access. With a same-host proxy and activated environment:

```text
python -m uvicorn app:app --app-dir backend --env-file backend/.env --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips 127.0.0.1
```

Preserve the public Host and forward the original HTTPS scheme. For a remote proxy, bind a private management interface, trust only the actual proxy IP, and firewall access to that proxy. Avoid wildcard forwarded-header trust. Verify HTTPS sign-in/logout, read-only access, and denied unauthorized actions before sharing.

Mist token requests require approved HTTPS origins, verified certificates, and no credentialed redirects. LDAP requires verified LDAPS; SSH rejects untrusted keys. Pages/APIs, including API docs, require authentication apart from login/static assets. Browser changes use CSRF protection.

### Firewall requirements

| Flow | Destination / port | Purpose |
| --- | --- | --- |
| Operator → HTTPS proxy | Deployment hostname, TCP 443 | Shared UI. Local examples use loopback TCP 8000. |
| Trusted proxy → app | Private/loopback bind, Uvicorn TCP port | Restricted backend access; `API_PORT` is quickstart-only. |
| App → Mist | Approved regional API hosts, TCP 443 | Discovery, audits, comparisons, authorized changes. |
| App → device library | `api.github.com`, `raw.githubusercontent.com`, custom library hosts, TCP 443 | Model lists and Juniper port metadata. |
| App → legacy switches | TCP 22 | SSH collection/baselines. |
| App → LDAP directory | TCP 636 or configured LDAPS port | User/service binds and session validation. |
| App → optional syslog | UDP 514 or `SYSLOG_PORT` | Action-log forwarding. |
| Setup/update host → source/package services | GitHub, configured Python/npm registries and artifact hosts, usually TCP 443 | Clone/update/install; npm/browser downloads are development-only. |

Provide DNS resolution. Mirrors/custom URLs may need more destinations. Browser assets are local; normal use needs no Tailwind/Sortable CDN.

## Operations and maintenance

### Start, stop, and restart

Start from the root with `python quickstart.py` or the manual command; stop the foreground server with Ctrl+C. With reboot startup installed, use `python quickstart.py stop`, `restart`, and `status`. The installer sets working directory, virtual-environment Python, environment loading, and restart/logging behavior. Configure shared HTTPS hosting and trusted proxy settings separately.

Restart after environment/direct policy edits. SSH execution and baseline-job tracking are process-local: use a **single Uvicorn worker**, keep baseline polling active until saved, and avoid restarting during collection. Temporary jobs do not resume after restart; retry interrupted collections.

### Controlled upgrades

1. Finish SSH/baseline jobs and take the backup below. Upgrades interrupt a managed running instance; unfinished process-local jobs do not resume.
2. Preserve/review all tracked and nonignored untracked work. Set `QUICKSTART_REPO_URL` and `QUICKSTART_BRANCH` in `backend/.env` for your intended upstream/fork. Defaults are `ejstover/GreatMigration` and `main`. A command-line `--repo`/`--branch` overrides only that invocation. Precedence is CLI, environment file, inherited process environment, built-in defaults.
3. Run `python quickstart.py upgrade`. Fetch and ancestry checks happen before stopping anything; the source, branch, current revision, and intended revision are displayed. The command requires a clean checkout and a fast-forward from both the current checkout and any existing requested local branch. It never changes `origin`, stashes, resets, rebases, or forces history. Stop foreground/manual instances yourself first.
4. The command stops an OS-managed instance, updates the checkout, continues through the updated launcher, installs requirements, and runs security migration. Only a previously running service is restarted; `--no-start` leaves it stopped. An initially stopped app stays stopped. Selected revisions must support this launcher's upgrade protocol; otherwise use the manual procedure below.
5. Compare `.env.sample` with `backend/.env`, adopting new settings without overwriting policy/secrets. Start if needed, sign in, and verify site lookup, Standards, conversion preview, and passive audit before live actions.

The recovery journal is `backend/data/quickstart/upgrade.json`, with revisions, stage, and outcome. A failure after stopping leaves the service stopped; code, packages, and data are not rolled back automatically. Resolve the reported stage and review the deployed revision, then run `setup --no-start` and `start`. For Python-version changes, recreate the virtual environment deliberately. Keep backups outside the checkout.

For manual upgrades or old revisions without the quickstart protocol: stop the app, record `git rev-parse HEAD`, back up, review work, explicitly select the intended branch, and use `git pull --ff-only origin main` (substitute your source/branch). Install `backend/requirements.txt` with the environment's Python, compare environment settings, run `backend/security_setup.py`, then start and verify. Resolve divergence manually.

Setup replaces weak keys, migrates legacy inline accounts to salted hashes, clears inline credentials, and scrubs old HTTP payload copies from logs while preserving event metadata. It retains Mist token/unrelated settings. A changed key invalidates existing cookies; rerunning with a valid key does not revoke every session. Use `--revoke-sessions` when required.

### Backup and restore

Stop the app before a consistent filesystem backup, especially SQLite. Keep encrypted/restricted backups outside the repository. Include:

- `backend/.env`, configured local account file, and local policy JSON, especially `port_rules.local.json`, replacement rules, firmware, and `exceptions.json`.
- `backend/data/conversion_sets/`, `backend/data/network_state/`, and `backend/logs/` for saved mappings, baselines, comparisons, and action/audit history.
- Configured security database, external custom-model/CA/verified known-hosts files, deployed commit, dependencies, and service configuration. Session state is sensitive; revoke it on recovery.

Restore with the service stopped: recover the intended revision/dependencies and restore configured paths and permissions. From the root, use the virtual environment's Python (or activate it) and run:

```text
python backend/security_setup.py --env backend/.env
python backend/security_setup.py --env backend/.env --revoke-sessions
```

The utility reads the named file for credential setup; revocation also loads it into the process before opening the security database. Existing process variables take precedence, so remove a stale inherited `SECURITY_DB_PATH` or set it to the restored database before revoking. Substitute your environment-file path if different. Restart and repeat upgrade checks. Local restoration does **not** undo Mist/device changes; maintain a separately reviewed network rollback procedure.

### Logs and retention

Daily logs are `backend/logs/DDMMYYYY.log`, containing application events, HTTP metadata, and audit summaries. Audit history is reconstructed from these logs with a default 365-day lookup window; deleting logs removes history. Syslog is optional; local logging remains enabled if forwarding cannot be configured. Monitor forwarding and disk use separately.

Maintenance runs at startup and about every 60 seconds while the app runs:

| Data | Lifetime / action |
| --- | --- |
| Temporary `tmp_ssh_jobs/` captures | Cleanup defaults to one hour; active/leased jobs are protected. Running configs are sensitive. |
| Saved conversion sets/network-state runs | Default 30 days by modification age, configured by `NETWORK_DATA_RETENTION_DAYS`; deletes expired records and updates indexes. |
| SQLite sessions/rate limits/job leases | Expired rows removed during database access. One-hour sessions are separate from evidence retention. |
| Accounts, policy, firmware, exceptions, logs | Not deleted by evidence retention. Set separate backup/rotation/retention policies; revoked exception records remain. |

Restored evidence with old modification times can be cleaned immediately; set an appropriate retention period before recovery startup. Protect policy backups independently of temporary evidence.

## Troubleshooting

| Symptom | Check / next step |
| --- | --- |
| Missing/weak session key | Confirm `backend/.env`; run the environment's `python backend/security_setup.py`. |
| Missing account database / local sign-in fails | Create accounts with `--add-user` before startup; check `LOCAL_USERS_FILE` path/permissions. |
| `HTTPS is required` locally | Set exactly `SESSION_HTTPS_ONLY=false`, use loopback host/client, restart. For shared access, fix HTTPS/proxy forwarding. |
| `Unapproved host` | Add exact hostname without scheme/port to `APP_ALLOWED_HOSTS`; restart. |
| LDAP sign-in/session failure | Replace sample DNs; check LDAPS trust, service credentials, bases, and allowed groups. Review logs without publishing secrets. |
| Push unavailable / denied | Check local role or LDAP push group, token write scope, and action prerequisites. |
| Empty Standards | Check region/token/org, inventory filtering, cache timestamps, eligible tags. Recent non-empty cache is reused; refresh can return no eligible versions. |
| Port-rule edits ineffective | Check `port_rules.local.json` precedence; repair malformed files and restart after direct edits. Use UI validation/save. |
| Custom model lookup/save fails | Configure writable `NETBOX_LOCAL_DT` with existing parent and verify online library access. Local names do not replace port metadata. |
| SSH rejection/failure | Check verified service-account keys, TCP 22, credentials, privileged prompt, supported Cisco commands. Verify changed fingerprints before trusting. |
| Missing baseline/conversion set | Use the same stable project name, select a saved set, check job errors, wait for save confirmation. Recollect after interrupted/restarted jobs. |
| Missing/wrong-location MACs | Check source labels, target ports, endpoint activity, telemetry, and comparison limitations before declaring an outage. |
| Exception-store error | Preserve/restore/repair JSON and permissions. No findings are suppressed; affected fixes are blocked. |
| `Invalid CSRF token` | Reload/sign in again; preserve public origin through proxy. |
| `413`, `429`, concurrency/job-limit error | Reduce upload size/rate or wait for jobs; review app/proxy limits before changing settings. |
| Missing syslog after manual start | Use `--env-file backend/.env` before module initialization; check UDP routing/local logs. |
| Quickstart failure or stale checkout | Run `setup --no-start` for missing installation prerequisites; use explicit `upgrade` for newer code. Check the upgrade recovery journal and service log; see [quickstart](#quickstart-scripts). |

## Development verification

CI uses Python 3.11 and Node 24 on Windows/Linux. Activate the environment (or use its full Python path), then install developer tools/Chromium:

```text
python -m pip install -r backend/requirements-dev.txt
python -m playwright install chromium
```

Linux browser testing may need system dependencies; CI uses `python -m playwright install --with-deps chromium`. Run:

```text
python -m pytest backend tests -q
python -m ruff check backend quickstart.py scripts tests --select E9,F63,F7,F82
python -m pip_audit -r backend/requirements.txt
python -m pip_audit -r backend/requirements-dev.txt
python -m pip check
npm ci --ignore-scripts
npm run build:css
git diff --exit-code -- static/app.css
npm audit
```

Tests use synthetic infrastructure/isolated storage, including browser and SSH transport checks. Never use production credentials or make production changes in tests. Results describe the checked revision/environment, not a guarantee of vulnerability-free operation.

After template edits, rebuild/commit `static/app.css`. When updating Sortable, copy `Sortable.min.js` and `LICENSE` from pinned `node_modules/sortablejs` to `static/vendor/Sortable.min.js` and `static/vendor/Sortable.LICENSE`; verify exact matches. Keep dependencies, lockfiles, generated assets, and sources together.

PRs run dependency review/redacted secret scanning. Weekly checks and Dependabot help detect dependency issues; see [SECURITY.md](SECURITY.md) for reporting/support.

## Project components

The UI uses server-rendered templates, local Tailwind CSS, and browser JavaScript calling FastAPI endpoints.

| Components | Responsibility |
| --- | --- |
| `backend/app.py`, `templates/`, `static/` | Pages, API orchestration, previews, navigation/assets. |
| `backend/convertciscotojson.py`, `backend/push_mist_port_config.py` | Cisco parsing, rules, port mapping/model validation, payloads/push. |
| `backend/translate_showtech.py`, `backend/ssh_collect.py` | Hardware parsing/mapping and SSH collection. |
| `backend/conversion_sets.py`, `backend/network_state_snapshots.py` | Saved mappings, baselines, MAC reconciliation. |
| `backend/compliance.py`, `backend/audit_actions.py`, `backend/audit_fixes.py` | Audit checks, action identifiers, remediation. |
| `backend/audit_exceptions.py`, `backend/audit_exception_evidence.py`, `backend/audit_exception_guard.py` | Approval storage/matching and fix protection. |
| `backend/audit_history.py`, `backend/logging_utils.py`, `backend/http_logging.py` | Log-derived history, file/syslog logging, HTTP metadata. |
| `backend/auth_local.py`, `backend/auth_ldap.py`, `backend/session_store.py`, `backend/security.py`, `backend/security_setup.py` | Authentication, sessions, request/transport protections, setup/accounts. |
| `backend/maintenance.py` | Evidence and expired/orphaned job cleanup. |

The [README alignment review](docs/readme-review.md) records section coverage, implementation evidence, validation, and remaining code limitations from this update.
