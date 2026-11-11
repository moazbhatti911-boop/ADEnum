from adenum.utils import (account_disabled, filetime_to_datetime, is_stale,
                          password_never_expires)


def build_findings(users, privileged, stale_days):
    findings = []
    privileged_users = set()
    for members in privileged.values():
        privileged_users.update(members)

    severity = {"Domain Admins": "High", "Enterprise Admins": "High",
                "Schema Admins": "Medium"}
    for group, members in privileged.items():
        for sam in members:
            findings.append({
                "severity": severity.get(group, "Medium"),
                "account": sam,
                "finding": f"Member of {group}",
                "detail": f"{sam} is a member of the privileged group {group}.",
            })

    for user in users:
        sam = user["sam"]
        if password_never_expires(user["uac"]):
            findings.append({
                "severity": "High" if sam in privileged_users else "Medium",
                "account": sam,
                "finding": "Password never expires",
                "detail": "userAccountControl has the DONT_EXPIRE_PASSWORD flag (65536).",
            })
        last_logon = filetime_to_datetime(user["last_logon_raw"])
        if is_stale(last_logon, stale_days):
            when = last_logon.date().isoformat() if last_logon else "never"
            findings.append({
                "severity": "Low",
                "account": sam,
                "finding": "Stale account",
                "detail": f"Last logon: {when} (more than {stale_days} days ago).",
            })
        if sam in privileged_users and account_disabled(user["uac"]):
            findings.append({
                "severity": "High",
                "account": sam,
                "finding": "Disabled account is still privileged",
                "detail": f"{sam} is disabled but still a member of a privileged group.",
            })
    return findings
