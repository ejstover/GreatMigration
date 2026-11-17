# README alignment review

Reviewed 2026-11-17 against source revision `14283c8` and the accompanying documentation changes. The intended readers are network engineers and installation administrators. The original review changed documentation and sample settings only. The quickstart implementation follow-up below updates the launcher findings; the original application-review results remain historical.

## Outcome

The previous README covered the core migration features but omitted saved conversion sets and Network Snapshot, understated audit checks/remediations, and gave incomplete setup/operational guidance. The replacement puts setup and configuration before workflows and adds deployment, upgrades, recovery, retention, and troubleshooting.

Material corrections:

- Manual installation now explicitly copies the sample to `backend/.env`, generates the signing key, creates the account before local-auth startup, and uses Uvicorn `--env-file` before module imports.
- Initial manual accounts are read-only; quickstart's initial local account is explicitly described as push-enabled. Current local roles come from account records, not legacy `LOCAL_PUSH_USERS` when the database is configured.
- Listener flags are distinguished from quickstart-only `APP_HOST`/`API_PORT`. Both launchers now share a Python implementation; normal startup is offline and setup/upgrade are explicit.
- Firmware refresh is demand-driven with a 90-day cache threshold. AP `alpha` and switch `junos_suggested` filters, inventory filtering, and explicit organization-policy synchronization are described separately.
- Port-rule precedence and UI save locations are documented. Hardware replacement overrides are distinguished from base device mappings.
- `LEGACY_VLANS` adds to built-in `10,500-599`; `EXCLUDE_VLANS` affects temporary naming prefixes rather than deleting VLANs from output.
- All six remediation actions, active diagnostics, exception safeguards, saved mappings, and snapshot reconciliation are covered.
- Evidence retention is distinguished from sessions, logs, policy, and approvals. Recovery now explicitly selects the environment file and explains security-database precedence.
- `.env.sample` removes unused `STD_SW_VER`/`STD_AP_VER`, adds operational settings, and replaces example site-variable IP defaults with required names only. Operators must explicitly supply approved `key=value` defaults before using the missing-variable fix. Existing local files are not overwritten.

## Section review checklist

Every heading in the prior README is accounted for below. Entries grouped with `/` are the original parent/child headings reviewed together. Evidence links identify the implementation source; function names narrow the relevant behavior.

| Previous section | Disposition / current location | Implementation evidence |
| --- | --- | --- |
| GreatMigration introduction | Retain purpose; add snapshots, shared evidence, accurate permissions | [app.py](../backend/app.py): protected routes and `_ensure_push_allowed`; [security.py](../backend/security.py) |
| Table of contents | Replace with current operator-oriented anchors | New README headings and Markdown link validation |
| Feature overview | Correct frontend description and roles; move details to Operator workflows | [templates](../templates/); [auth_local.py](../backend/auth_local.py); [auth_ldap.py](../backend/auth_ldap.py) |
| Hardware conversion | Retain/condense; explain synthetic show-tech and mapping overlays | [translate_showtech.py](../backend/translate_showtech.py): `load_mapping`, `parse_showtech`; [ssh_collect.py](../backend/ssh_collect.py) |
| Port profile rules | Retain; add precedence and exact save location | [push_mist_port_config.py](../backend/push_mist_port_config.py): `load_rules`, `validate_rules_doc`; [app.py](../backend/app.py): `api_save_rules` |
| Standards | Correct installation/scheduler/read-only claims; add tags, inventory filter, explicit sync | [compliance.py](../backend/compliance.py): `_refresh_firmware_standards_if_needed`, `_row_matches_standard_firmware_filter`; [app.py](../backend/app.py): `api_standards_table`, `api_sync_standards` |
| Config conversion | Expand phase semantics, preview/apply boundaries, cleanup targeting, saved sets | [index.html](../templates/index.html); [app.py](../backend/app.py): `api_push_batch`, `_remove_temporary_config_for_rows` |
| Compliance audit & 1 Click Fix | Expand checks, six fixes, diagnostics; retain detailed exception semantics | [compliance.py](../backend/compliance.py): `DEFAULT_CHECKS`; [audit_actions.py](../backend/audit_actions.py); [audit_fixes.py](../backend/audit_fixes.py); [audit_exceptions.py](../backend/audit_exceptions.py) |
| Hamburger menu guide | Replace with compact route/purpose table | [app.py](../backend/app.py): `NAV_LINK_KEYS`, page routes |
| How the menu behaves | Remove unnecessary click/animation promises | Current templates/navigation; no setup or operations dependency |
| User/session behavior in the menu | Retain user/logout explanation; move roles/sessions to configuration | [auth_local.py](../backend/auth_local.py), [auth_ldap.py](../backend/auth_ldap.py): `/me`, POST `/logout`; [session_store.py](../backend/session_store.py) |
| Menu items and what each one does | Correct/condense and include Network Snapshot | [app.py](../backend/app.py): page routes |
| Recommended operator workflow using the menu | Replace with workflow instructions including pre-cutover baseline | [index.html](../templates/index.html): Snapshot Prep; [network_snapshot.html](../templates/network_snapshot.html) |
| Getting started | Reorganize into explicit platform paths and first sign-in | [quickstart.py](../quickstart.py); [security_setup.py](../backend/security_setup.py) |
| Prerequisites | Clarify Python 3.11 CI coverage, Linux venv package, runtime/development split | [security.yml](../.github/workflows/security.yml); [requirements.txt](../backend/requirements.txt); [package.json](../package.json) |
| Quick start scripts | Correct shared behavior, privileged initial account, flags and limitations | [quickstart.py](../quickstart.py); [quickstart.ps1](../quickstart.ps1) |
| Python (cross-platform) | Retain supported entry point; document clean-branch update behavior and bind settings | [quickstart.py](../quickstart.py): `main`, `ensure_git_repo`, `ensure_env_file`, `start_api` |
| PowerShell (Windows-friendly) | Delegate all workflows to Python; retain PowerShell command/option names | [quickstart.ps1](../quickstart.ps1): interpreter selection and argument forwarding |
| Manual setup | Replace with complete Windows/Linux commands; samples are usable without mandatory JSON copying | [security_setup.py](../backend/security_setup.py); [auth_local.py](../backend/auth_local.py): `_load_users`; rule/mapping loaders |
| First-run checklist | Correct ordering and add explicit read-only validation/SSH trust | [security.py](../backend/security.py); [ssh_collect.py](../backend/ssh_collect.py): `_collect_device` |
| Extras: LDAP, syslog, and logging | Merge into configuration/operations; document UDP and early initialization | [auth_ldap.py](../backend/auth_ldap.py); [logging_utils.py](../backend/logging_utils.py); [http_logging.py](../backend/http_logging.py) |
| Backend Python components | Retain as Project components; include snapshots, exceptions, sessions, maintenance | Current backend module inventory |
| Configuration reference | Expand to all literal runtime environment reads plus dynamic policy/helper settings | Backend environment reads; [quickstart.py](../quickstart.py); [.env.sample](../.env.sample) |
| Authentication and roles | Correct legacy role reference; document LDAP group semantics and revocation | [auth_local.py](../backend/auth_local.py): loaders/current user; [auth_ldap.py](../backend/auth_ldap.py): login/current user |
| Mist connectivity | Expand region allowlist, process/file precedence, token permissions | [security.py](../backend/security.py): `mist_base_url`, `validate_mist_request`; [app.py](../backend/app.py): dotenv loading |
| Compliance policy tuning | Correct unused firmware variables; add defaults/formats and naming-algorithm limit | [compliance.py](../backend/compliance.py): policy constants/loaders; [audit_fixes.py](../backend/audit_fixes.py) |
| VLAN/reserved behavior for conversion safety | Correct default preservation and EXCLUDE semantics | [app.py](../backend/app.py): `_expand_vlan_id_set`, `_should_use_legacy_prefix`, reserved VLAN map |
| 1 Click Fix safeguards | Merge into complete action/prerequisite table and approval safeguards | [audit_fixes.py](../backend/audit_fixes.py); [audit_exception_guard.py](../backend/audit_exception_guard.py) |
| Firewall requirements | Correct flow direction; add proxy, raw GitHub, UDP syslog, setup services | [app.py](../backend/app.py): library URLs; [logging_utils.py](../backend/logging_utils.py): `SysLogHandler`; SSH/LDAP transports |
| Operational tips | Replace with concrete controlled upgrades, consistent backups, recovery and logs | Quickstart Git behavior; [security_setup.py](../backend/security_setup.py); storage modules |
| Secure deployment and verification | Retain anchor; group hosting/trust requirements; update SECURITY.md links | [security.py](../backend/security.py); [SECURITY.md](../SECURITY.md) |
| Installation and account migration | Move to accounts/upgrades; correct unconditional session invalidation claim | [security_setup.py](../backend/security_setup.py): `upgrade_env`, CLI; [session_store.py](../backend/session_store.py) |
| Hosting, credentials, and trusted connections | Retain/expand concrete proxy command and single-worker collection limit | [security.py](../backend/security.py); [ssh_collect.py](../backend/ssh_collect.py): in-memory jobs; [app.py](../backend/app.py): `SNAPSHOT_BASELINE_JOBS` |
| Evidence retention and resource limits | Split configuration and precise retention table | [maintenance.py](../backend/maintenance.py); [security.py](../backend/security.py): `security_db`; [ssh_collect.py](../backend/ssh_collect.py): `cleanup_old_jobs` |
| Development verification | Retain CI commands, local assets and reporting; distinguish verification scope | [security.yml](../.github/workflows/security.yml); [build-css.mjs](../scripts/build-css.mjs); requirements and package manifest |

Added sections cover saved conversion sets, Network Snapshot, backups/restoration, explicit start/stop/restart, and troubleshooting. Their primary evidence is [conversion_sets.py](../backend/conversion_sets.py), [network_state_snapshots.py](../backend/network_state_snapshots.py), relevant API/page handlers, and the storage/authentication modules listed above.

## Remaining code and setup defects

The original documentation review recorded these findings. The quickstart follow-up fixes the three launcher defects listed below; remaining application/manual-start limitations are still documented.

| Finding | Evidence / confirmation | Documented alternative |
| --- | --- | --- |
| Fixed: PowerShell rejected nonexistent clone targets | Wrapper forwards the target to shared Python setup without `Resolve-Path`. | Use explicit `setup --dir` / `setup -TargetDir`. |
| Fixed: empty PowerShell Git status caused a null-method error | All Git handling now uses Python subprocess results; PowerShell contains no Git workflow. | Covered by local clean-checkout upgrade tests. |
| Fixed: branch switching skipped the intended update | Upgrade fetches an explicit revision, validates ancestry, switches/creates the target branch, and fast-forwards to that revision. | Normal start/setup never updates an existing checkout. |
| Bare manual Uvicorn startup can miss file-only syslog configuration | `http_logging`/`logging_utils` initialize before `app.py` calls dotenv. Early initialization confirmed by import order. | Use `--env-file backend/.env`, or process-level settings before startup. |
| Unset help URL still references the older repository | `README_URL` constants in app/local/LDAP auth point to `jacob-hopkins`; configured sample uses current Git remote `ejstover`. | Keep explicit `HELP_URL`. |
| Quickstart LDAP generation is incomplete for a real directory | Generation now includes `READONLY_GROUP_DN`, but deployment-specific directory/group placeholders still require operator review before startup. | Setup-only mode, explicitly configure all directory/group values, then start manually. |

Additional operational limitations requiring deliberate handling:

- AP firmware selection is hardcoded to `alpha`, and built-in legacy VLAN preservation cannot be subtracted through `LEGACY_VLANS`. These are current behavior/policy decisions, not claims of recommended organization policy.
- Rule UI reads fail visibly on a malformed highest-priority file, while conversion's loader falls back. Direct rule-file changes and saves in other worker processes may not refresh in-memory rules immediately.
- SSH jobs and baseline bookkeeping are process-local even though capacity leases/sessions use shared SQLite. A single worker is recommended; unfinished jobs do not resume after restart. Baseline saving occurs during job polling.
- Local custom model names still depend on online model listing; custom names do not provide physical port layouts, and saving requires an existing parent directory.
- Snapshot reconciliation matches MAC locations rather than VLAN/service health; project-name normalization can cause distinct display names to share a storage key.

## Quickstart implementation follow-up

The launcher now separates offline startup, setup, explicit fast-forward upgrade,
service controls, and reboot registration. PowerShell delegates to Python. New
helpers provide single-worker runtime locking/environment loading and native
Windows Task Scheduler, Linux systemd, and macOS launchd definitions. Upgrades
preserve `origin`, refuse local work/divergence, and continue through the updated
launcher with a stage/revision recovery journal.

Windows/Python 3.11 validation: the full backend/launcher run passed **412 tests**
(355 existing backend tests plus the initial 57 launcher cases), with 45 existing
dependency/API deprecation warnings. Expanded launcher verification passed all
**69 cases** across the complete launcher run and the final focused recheck.
Launcher cases include real local-Git fetch/update/updated-launcher continuation,
real synthetic ASGI process startup/shutdown, environment loading before imports,
wrong-nonce rejection, maintenance locking, PowerShell option/exit-code forwarding,
branch creation/switching, and mocked native registration/control/recovery. Ruff's fatal-error
selection passed. A restricted initial run blocked Git's local transport and
loopback connections; the isolated suite passed with those accesses permitted.

No actual tasks/services were installed and no machine was rebooted. Linux/macOS
execution and native boot behavior are not verified by this Windows run. CI now
includes launcher tests on all three platforms; the [native smoke checklist](quickstart-validation.md)
remains a separate release gate. No production credentials, package updates,
application API changes, or frontend asset changes were needed for this follow-up.

## Validation performed

Windows, Python **3.11.0**, 2026-11-17:

- **355 tests passed**, including browser, local/LDAP authentication, permissions, SSH transport, security regressions, audit exceptions/fixes, standards, conversion sets, snapshot comparison, conversion/lifecycle, and CLI tests. The run emitted 45 dependency/API deprecation warnings; no test failures remained.
- The initial restricted runs encountered temporary-file replacement denial and stalled in Windows asyncio's local socket-pair initialization. Rerunning with local-server/file access and a dedicated ignored test directory passed the complete suite. These failures were execution-environment restrictions, not established application regressions.
- A temporary checkout copied tracked runtime sources and samples only, never the installation's `.env`, account data, or evidence. With synthetic credentials, it passed sample copying, key generation, hidden-prompt account creation/promotion/demotion, Uvicorn `--env-file` startup, read-only login and `/me`, and session revocation. No external Mist, LDAP, or device connections were made.
- Created a fresh Python 3.11 virtual environment and confirmed its pip. Runtime startup used the existing environment's installed dependencies; a new network-based dependency installation was not performed.
- Exercised helper initialization against scratch files; reproduced branch-update behavior with mocked subprocesses. Full quickstart clone/update/install was not run against the working checkout.
- PowerShell parser accepted the quickstart script and all three README PowerShell command blocks. PowerShell defect reproductions performed no repository mutations.
- Inventory checks covered **42 sample settings**, including commented optional settings, and **38 literal backend environment reads**; each is documented. Policy-helper settings with dynamically selected names were cross-checked separately. Sample secure-cookie, account-path, and no-site-IP-default invariants passed.
- Local Markdown links/anchors, referenced paths, CLI options, UI phase labels, and route names were checked against the repository. Ruff's documented fatal-error selection and `pip check` passed.
- An independent reader reviewed fresh setup, roles/revocation, preview/live phases, snapshots, troubleshooting, upgrades, recovery, firmware, and listener flags. One recovery-environment ambiguity was corrected; the reader confirmed the revision resolves it.

Linux instructions were checked against repository code and the Windows/Linux CI definition; they were not executed on Linux during this review. PowerShell 5.1/macOS, real Mist/LDAP/device access, shared-proxy deployment, dependency vulnerability scans, and network package downloads were not exercised. No CSS/dependency changes were made, so frontend rebuilding/audits were not rerun for this documentation-only update.

## Maintenance acceptance checklist

- [x] Original README headings mapped to retain/correct/expand/remove decisions.
- [x] Setup, configuration, permissions, workflow effects, paths, and retention verified against code.
- [x] Runtime and legacy settings distinguished; secure sample defaults preserved.
- [x] Windows setup/account/startup checks use scratch data and synthetic credentials.
- [x] Existing relevant tests and complete backend suite pass with required local test access.
- [x] Independent reader questions answered and identified gap corrected.
- [x] Remaining code limitations recorded separately; executable code/dependencies unchanged.
- [x] Platform/network verification limits stated explicitly.
