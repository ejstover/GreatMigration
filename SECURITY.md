# Security policy

## Supported versions

Security fixes are provided for the latest commit on `main`. Older commits and
feature branches are not maintained for security fixes. Update to `main` before
reporting an issue when it is safe to do so.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/ejstover/GreatMigration/security/advisories/new)
to report suspected vulnerabilities confidentially. Do not open a public issue or
pull request containing exploit details, credentials, or customer network data.

Include the affected commit, deployment conditions, impact, and reproduction steps
using synthetic data. Never include live Mist tokens, passwords, session cookies,
private keys, or unredacted device configurations. Please allow time for a fix
before public disclosure; no response-time guarantee is currently offered.

If a credential has been published, revoke or rotate it immediately. Removing a
file or commit does not make an exposed credential safe to reuse.

## Deployment

See the [README security guidance](README.md#secure-deployment-and-verification)
for HTTPS, LDAP and SSH trust, and network access requirements, and
[operations and maintenance](README.md#operations-and-maintenance) for account
migration, backups, recovery, and retention. Validation commands are under
[development verification](README.md#development-verification).
GreatMigration is intended for trusted operators on a restricted management
network. Authenticated users share the installation's network evidence and Mist
service account; it is not a tenant-isolation boundary.
