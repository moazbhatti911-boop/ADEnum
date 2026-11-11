from adenum.findings import build_findings


def _user(sam, uac=512, last_logon_raw=0):
    return {"sam": sam, "dn": f"CN={sam},DC=lab,DC=local", "uac": uac,
            "last_logon_raw": last_logon_raw, "member_of": []}


def test_privileged_and_never_expires():
    users = [_user("alice", uac=66048), _user("bob")]
    privileged = {"Domain Admins": ["alice"], "Enterprise Admins": [], "Schema Admins": []}
    findings = build_findings(users, privileged, stale_days=90)
    texts = [(f["account"], f["finding"], f["severity"]) for f in findings]
    assert ("alice", "Member of Domain Admins", "High") in texts
    assert ("alice", "Password never expires", "High") in texts


def test_nested_group_expansion():
    from adenum.queries import expand_members
    groups_by_dn = {"CN=Admins,DC=lab,DC=local": {"members": ["CN=carol,DC=lab,DC=local"]}}
    users_by_dn = {"CN=carol,DC=lab,DC=local": "carol"}
    assert expand_members(["CN=Admins,DC=lab,DC=local"], groups_by_dn, users_by_dn) == ["carol"]
