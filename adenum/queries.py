from ldap3 import SUBTREE

USER_ATTRS = ["sAMAccountName", "distinguishedName", "memberOf",
              "userAccountControl", "lastLogonTimestamp"]
GROUP_ATTRS = ["cn", "distinguishedName", "member", "sAMAccountName"]
COMPUTER_ATTRS = ["cn", "operatingSystem", "dNSHostName"]

PRIVILEGED_GROUPS = ["Domain Admins", "Enterprise Admins", "Schema Admins"]


def search_all(conn, base_dn, search_filter, attributes):
    """Paged search, so a domain with more than 1000 objects still works."""
    entries = []
    for entry in conn.extend.standard.paged_search(
        search_base=base_dn, search_filter=search_filter,
        search_scope=SUBTREE, attributes=attributes,
        paged_size=500, generator=True,
    ):
        if entry.get("type") != "searchResEntry":
            continue
        entries.append(entry["attributes"])
    return entries


def _first(attrs, name):
    values = attrs.get(name)
    if not values:
        return None
    return values[0] if isinstance(values, list) else values


def get_users(conn, base_dn):
    users = []
    for attrs in search_all(conn, base_dn, "(objectClass=user)", USER_ATTRS):
        users.append({
            "sam": _first(attrs, "sAMAccountName"),
            "dn": _first(attrs, "distinguishedName"),
            "member_of": attrs.get("memberOf") or [],
            "uac": _first(attrs, "userAccountControl"),
            "last_logon_raw": _first(attrs, "lastLogonTimestamp"),
        })
    return [u for u in users if u["sam"]]


def get_groups(conn, base_dn):
    groups = {}
    for attrs in search_all(conn, base_dn, "(objectClass=group)", GROUP_ATTRS):
        cn = _first(attrs, "cn")
        if cn:
            groups[cn] = {
                "dn": _first(attrs, "distinguishedName"),
                "members": attrs.get("member") or [],
            }
    return groups


def get_computers(conn, base_dn):
    computers = []
    for attrs in search_all(conn, base_dn, "(objectClass=computer)", COMPUTER_ATTRS):
        computers.append({
            "name": _first(attrs, "cn"),
            "os": _first(attrs, "operatingSystem") or "unknown",
            "dns": _first(attrs, "dNSHostName"),
        })
    return computers


def expand_members(member_dns, groups_by_dn, users_by_dn, visited=None):
    """Resolve group members to usernames, following nested groups."""
    visited = visited or set()
    result = []
    for dn in member_dns:
        if dn in visited:
            continue
        visited.add(dn)
        if dn in users_by_dn:
            result.append(users_by_dn[dn])
        elif dn in groups_by_dn:
            result.extend(expand_members(groups_by_dn[dn]["members"],
                                         groups_by_dn, users_by_dn, visited))
    return sorted(set(result))


def get_privileged_members(groups, users_by_dn):
    """{group name: [usernames]} for Domain / Enterprise / Schema Admins."""
    groups_by_dn = {g["dn"]: g for g in groups.values() if g["dn"]}
    result = {}
    for name in PRIVILEGED_GROUPS:
        group = groups.get(name)
        if group is None:
            result[name] = []
        else:
            result[name] = expand_members(group["members"], groups_by_dn, users_by_dn)
    return result
