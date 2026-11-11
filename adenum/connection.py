from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPBindError, LDAPExceptionError, LDAPSocketOpenError


def connect(dc, username, password, domain, port=389, use_ssl=False):
    """Bind to the lab DC. Raises a clear message, never a crash.

    username: the read-only lab account name, e.g. audit-read
    domain:   e.g. lab.local — the login becomes audit-read@lab.local
    """
    server = Server(dc, port=port, use_ssl=use_ssl, get_info=ALL)
    user = f"{username}@{domain}"
    conn = Connection(server, user=user, password=password, auto_bind=False)
    try:
        if not conn.bind():
            raise LDAPBindError("Login failed: wrong username or password.")
    except LDAPSocketOpenError:
        raise ConnectionError(
            f"Cannot reach the domain controller at {dc}:{port}. "
            "Check the DC is switched on and the address is correct."
        )
    except LDAPBindError:
        raise
    except LDAPExceptionError as e:
        raise ConnectionError(f"Login failed: {e}")
    if not conn.bound:
        raise LDAPBindError("Login failed: wrong username or password.")
    return conn
