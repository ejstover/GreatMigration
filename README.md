# GreatMigration

Tools for converting Cisco switch port configurations and pushing them to Mist.

Copy `backend/.env.sample` to `backend/.env` and update the values with your own
credentials before running the backend.

## Authentication

The backend supports pluggable authentication and **requires** the `AUTH_METHOD`
environment variable to be set. If it's missing, the server responds with a setup
page that links back to this README. Choose one of the following values:

- `local` – authenticate against a list of username/password pairs stored in the
  `LOCAL_USERS` environment variable (`user1:pass1,user2:pass2`). Users listed in
  `LOCAL_PUSH_USERS` (comma‑separated usernames) are granted push rights.
- `ldap` – authenticate against Active Directory. Defaults assume a demo domain
  `testdomain.local` and a read‑only service account `GreatMigration`.

### LDAP settings

Override these environment variables as needed:

- `LDAP_SERVER_URL` (default `ldaps://dc01.testdomain.local:636`)
- `LDAP_SEARCH_BASE` (default `DC=testdomain,DC=local`)
- `LDAP_BIND_TEMPLATE` (default `{username}@testdomain.local`)
- `PUSH_GROUP_DN` – group DN whose members may push
- `LDAP_SERVICE_DN` (default `CN=GreatMigration,CN=Users,DC=testdomain,DC=local`)
- `LDAP_SERVICE_PASSWORD`

All modes require `SESSION_SECRET` to sign session cookies.

## Requirements

Install dependencies with

```
pip install -r backend/requirements.txt
```

Start the API with

```
uvicorn app:app --app-dir backend --reload
```