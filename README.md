# ADEnum

Your own Active Directory enumeration tool, written in Python with `ldap3`.

Give it your lab domain controller and a read-only lab account, and it lists
users, groups and privileged accounts, then prints a report of the interesting
findings — who is in Domain Admins, which accounts never expire their
passwords, and which accounts have not logged in for a long time.

Lab only. Run ADEnum only against your own lab domain controller, on your own
lab network, with an account you own or have written permission to use. Never
run it against a real company network — that is unauthorized access.
Unauthorized access is a criminal offence under the Prevention of Electronic
Crimes Act, 2016 (Pakistan).

## Features

- Connect to the lab DC with `ldap3`, password asked at run time with `getpass`
- List all users (`sAMAccountName`) and all groups
- List members of Domain Admins, Enterprise Admins, Schema Admins
- Flag password-never-expires accounts (`userAccountControl` flag 65536)
- Flag stale accounts (`lastLogonTimestamp`, default 90 days)
- Findings report with severity, saved to a text file
- Stretch: list computers and operating systems, nested group membership, CSV export

## Installation

Kali Linux:

```bash
cd ADEnum
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
cd ADEnum
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python -m adenum --dc 192.168.56.10 --domain lab.local --username audit-read
```

You will be asked for the password — it is never written in the code and never
saved to a file. Replace `192.168.56.10` with your lab DC address and `lab.local`
with your lab domain.

Options:

```
--dc          Lab domain controller address (required)
--domain      Lab domain, e.g. lab.local (required)
--username    Read-only lab account name (required)
--base-dn     Base DN, default is derived from --domain
--port        LDAP port, default 389 (636 with --use-ssl)
--use-ssl     Use LDAPS
--stale-days  Days without a logon before an account is stale, default 90
--output      Report text file, default report.txt
--csv         Also write findings to this CSV file
```

Example with CSV:

```bash
python -m adenum --dc 192.168.56.10 --domain lab.local --username audit-read --csv report.csv
```

## Running on Kali Linux

```bash
cd /home/luffy/ADEnum
source venv/bin/activate
python3 -m adenum --dc 192.168.56.10 --domain lab.local --username audit-read --csv report.csv
```

Then read `report.txt` from start to finish — that is Step 6 of the PDF.

## What each finding means

| Finding | Severity | Why it matters | How to fix it |
| --- | --- | --- | --- |
| Member of Domain Admins | High | Full control of the domain | Remove the account unless it truly needs it |
| Member of Enterprise Admins | High | Full control of the forest | Remove the account unless it truly needs it |
| Member of Schema Admins | Medium | Can change the AD schema | Remove the account unless it truly needs it |
| Password never expires | Medium | A stolen password never stops working | Clear the flag, set a password policy |
| Stale account | Low | Forgotten accounts are easy targets | Disable, then delete if no longer needed |
| Disabled account is still privileged | High | A re-enabled account is instantly an admin | Remove it from the privileged group |

## Testing

Unit tests (no live DC needed):

```bash
pytest -q
```

Lab tests (on your own lab DC only):

1. Wrong password must fail with a clear message, not a crash.
2. User count must match Active Directory Users and Computers.
3. Domain Admins must appear in the privileged list.
4. Create a test account with password-never-expires and check it appears.
5. With the DC switched off, you must get a clear error, not a crash.

## Project Structure

```
adenum/   - main.py, connection.py, queries.py, findings.py, report.py, utils.py
tests/    - pytest tests for findings, utils and report
docs/     - architecture, testing
samples/  - sample report from a lab domain
```

## Security

- Lab only, own domain controller only.
- Read-only lab account — use the lowest privilege that can read the directory.
- Password is asked with `getpass` and never stored.
- No exploitation, no password attacks, no changes to the domain — ADEnum only reads.
