# Architecture

CLI (`adenum/main.py`) → `connection.py` binds with ldap3 → `queries.py`
searches users, groups and computers → `findings.py` applies the rules →
`report.py` prints the report and saves it to a text file (and CSV, if asked).

- `connection.py` — bind to the lab DC, clear error on wrong password or unreachable DC.
- `queries.py` — paged LDAP search, privileged-group members with nested-group expansion.
- `utils.py` — base DN, Windows FILETIME conversion, userAccountControl flags, stale check.
- `findings.py` — privileged membership, password-never-expires, stale accounts, disabled-but-privileged.
- `report.py` — text report and CSV export.
