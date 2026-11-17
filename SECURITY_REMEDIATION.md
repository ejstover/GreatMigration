# Security remediation and verification

This change addresses the November 17, 2026 assessment of the current working tree: three critical, seven high, seven medium, and two low findings. Existing migration, hardware, audit, exception, and snapshot features remain supported. Infrastructure calls in automated tests use synthetic services; production changes are never needed for verification.

## Findings and regression coverage

| ID | Correction | Verification |
| --- | --- | --- |
| C-01 | Conversion uploads reject absolute paths, traversal, separators, and null bytes before writing. | Real multipart HTTP requests with Windows/POSIX attack filenames; successful browser conversion. |
| C-02 | Mist requests permit only administrator-approved HTTPS API origins; the outbound hook blocks credentialed redirects and disabled certificate checks. | Destination attacks rejected before network access; synthetic token forwarding inspected. |
| C-03 | Startup rejects missing/weak signing keys. Setup generates random keys. Cookies contain only a signed opaque identifier for server-side sessions. | Weak-key and forged legacy-cookie regressions; idempotent migration tests. |
| H-01 | A default-deny middleware authenticates all application/API/docs routes before body parsing. Single push checks live-push rights and supplies the formerly missing helper argument. | Anonymous route matrix; read-only preview/live-push tests; authenticated browser workflows. |
| H-02 | Saved-record identifiers use a restricted grammar and resolved path containment. | Absolute/traversal identifier rejection and existing snapshot/conversion-set tests. |
| H-03 | Rule names use DOM value assignment; site names and errors are escaped. Nonce-based CSP blocks injected script and event handlers. | Real Chromium pages with malicious rule/site names; no injected elements, executed markers, or CSP violations. |
| H-04 | Standards refresh never changes Mist settings. Organization synchronization is an explicit push-gated POST. Cable diagnostics require privileged opt-in. | Passive-refresh/no-PUT assertion; explicit sync success/failure; read-only diagnostic rejection. |
| H-05 | LDAP requires validating LDAPS with a trusted CA. SSH requires known host keys. | LDAP configuration tests and real Netmiko/Paramiko connections to a local simulated switch with trusted/untrusted keys. |
| H-06 | HTTP logs record method/host/status only. Request queries and timing metadata values are omitted. Setup removes legacy payload copies from old logs. | Synthetic secret logging regression and historical payload scrubbing tests. |
| H-07 | Runtime dependencies are upgraded and constrained to audited versions. Body, upload-count, VLAN/member-range, in-flight, request-rate, and shared SSH-job limits bound work. | Dependency audit, package compatibility check, quota/range/body tests, functional suite. |
| M-01 | Shared rules, replacements, and custom device types require push privileges. | Role matrix against actual HTTP routes. |
| M-02 | Quick-start binds to loopback. Remote requests require HTTPS and an approved host; HTTPS responses always use Secure cookies. | Remote HTTP/untrusted-host rejection and startup syntax checks. |
| M-03 | Local credentials use salted scrypt hashes. New quick-start passwords require 12 characters. Login attempts are rate limited. | Hash verification, plaintext rejection, idempotent migration, login throttling. |
| M-04 | Sessions have a one-hour absolute lifetime, server-side revocation, identifier rotation, and logout invalidation. Local credential/role edits revoke existing sessions. LDAP sessions revalidate directory membership on each request. | Cookie replay, expiry, role-change, and directory-revocation tests. |
| M-05 | Wildcard credentialed CORS is removed. Unsafe requests require a session-bound CSRF token and reject foreign origins. Logout uses POST. | Missing/wrong token, foreign origin, and real browser fetch/logout tests. |
| M-06 | LDAP identity and UPN filters escape metacharacters. | Identity-injection and existing membership-filter tests. |
| M-07 | Local data is excluded from Git. Periodic retention removes expired evidence and orphaned SSH captures after restarts. | Evidence/index retention, orphan cleanup, active-job preservation, and browser workspace-isolation checks. |
| L-01 | Audit logging tags events on the server, stores audit counts as structured JSON, and escapes line breaks. Generic messages cannot impersonate an audit event; legacy history remains readable. | Multiline/inline marker injection, structured history, and legacy history regressions. |
| L-02 | CSS and Sortable are served locally. Responses include CSP, frame restrictions, nosniff, cache controls, referrer policy, and HSTS on HTTPS. | Browser checks for every page and response-header assertions. |

Browser tests explicitly isolate both evidence roots; regression checks ensure they do not modify workspace evidence.

## Installation and compatibility

Run `python backend/security_setup.py` before starting an existing installation. Quick-start does this automatically. It replaces weak signing keys, migrates legacy local accounts to `backend/data/local_users.json`, removes plaintext account entries from `.env`, and scrubs old HTTP body logs. It preserves the Mist token and unrelated settings. Existing sessions require a new login.

Use `python backend/security_setup.py --add-user USERNAME --push` to create/update a push-enabled local account, or omit `--push` for a read-only account. Passwords are entered through a hidden prompt. `--revoke-sessions` revokes all installation sessions. File-backed local account/role changes take effect on the next request.

For shared hosting, configure `APP_ALLOWED_HOSTS` with the exact public hostname, use HTTPS through a trusted reverse proxy, and retain `SESSION_HTTPS_ONLY=true`. Uvicorn must trust forwarded headers only from that proxy. Quick-start's HTTP exception applies only to loopback clients and loopback hostnames.

`MIST_BASE_URL` selects the default region. Additional exact region hosts may be configured in `MIST_ALLOWED_HOSTS`. Arbitrary request-supplied API origins, plain HTTP, credentialed redirects, and disabled TLS verification are rejected.

LDAP requires `ldaps://`, a CA trusted by the host or `LDAP_CA_CERTS_FILE`, and the service account credentials for ongoing authorization checks. Unavailable directory validation fails closed. SSH collection requires verified keys in the normal known-hosts file or `SSH_KNOWN_HOSTS_FILE`; add keys only after verifying their fingerprints through a trusted channel.

Standards viewing still refreshes the local firmware reference. Push-enabled users explicitly apply Standard 1 to the organization onboarding policy with the Standards button. Audit runs are passive by default; push-enabled users can opt into active cable diagnostics.

Defaults: 16 MiB request bodies, 16 uploaded files, eight in-flight requests per process, two shared SSH jobs, at most eight SSH workers per job, one-hour temporary SSH retention, and 30-day saved evidence retention. `MAX_REQUEST_BYTES`, `MAX_INFLIGHT_REQUESTS`, `MAX_SSH_JOBS`, and `NETWORK_DATA_RETENTION_DAYS` configure the respective limits. Evidence retention excludes local accounts, sessions, and approved audit exceptions. Keep policy/configuration backups with access restricted to the service account and administrators.

Frontend assets are committed. Rebuild after template changes with `npm ci --ignore-scripts` and `npm run build:css`; copy the pinned Sortable asset from `node_modules/sortablejs` if changing that dependency. Node is needed only to rebuild assets.

## Reproducible validation

Install Python test tools with `python -m pip install -r backend/requirements-dev.txt`, then install the test browser with `python -m playwright install chromium`.

Run:

```text
python -m pytest backend -q
python -m pip_audit -r backend/requirements.txt
python -m pip check
python -m compileall -q backend quickstart.py
```

The suite covers conversion/mapping, hardware/PDF output, rules, firmware standards, compliance checks, audit fixes, exception approval/revocation, conversion sets, MAC-state comparison, previews/lifecycle behavior, authentication, server sessions, LDAP, SSH, CLI entry points, and real-browser page/upload/logout flows. HTTP requests to production infrastructure are blocked in tests. The local browser and SSH servers use synthetic credentials and isolated storage.

Live production Mist writes, a real corporate LDAP directory, and physical switches are intentionally simulated. A deployment still needs its own certificates, directory service account, verified SSH host keys, and approved network access.

## Verified local result

- 337 tests passed on Windows/Python 3.11, including Chromium and real SSH transport tests against isolated local servers.
- Clean requirements resolution: 60 runtime packages, zero known vulnerabilities.
- npm audit: zero known vulnerabilities.
- Package compatibility, Python compilation, PowerShell syntax, static undefined-name checks, and whitespace checks passed.
- The pinned CI workflow runs the same checks on Windows and Linux.
