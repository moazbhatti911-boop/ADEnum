import argparse
import getpass
import sys

from adenum.connection import connect
from adenum.findings import build_findings
from adenum.queries import (get_computers, get_groups, get_privileged_members,
                            get_users)
from adenum.report import format_report, write_csv_report, write_text_report
from adenum.utils import domain_to_base_dn


def main():
    parser = argparse.ArgumentParser(prog="adenum", description="ADEnum — Active Directory enumeration for your own lab only.")
    parser.add_argument("--dc", required=True, help="Lab domain controller address, e.g. 192.168.56.10")
    parser.add_argument("--domain", required=True, help="Lab domain, e.g. lab.local")
    parser.add_argument("--username", required=True, help="Read-only lab account name, e.g. audit-read")
    parser.add_argument("--base-dn", default=None, help="Base DN, default is derived from --domain")
    parser.add_argument("--port", type=int, default=389)
    parser.add_argument("--use-ssl", action="store_true", help="Use LDAPS (port 636)")
    parser.add_argument("--stale-days", type=int, default=90)
    parser.add_argument("--output", default="report.txt")
    parser.add_argument("--csv", default=None, help="Also write findings to this CSV file")
    args = parser.parse_args()

    if args.use_ssl and args.port == 389:
        args.port = 636
    base_dn = args.base_dn or domain_to_base_dn(args.domain)
    password = getpass.getpass(f"Password for {args.username}@{args.domain}: ")

    try:
        conn = connect(args.dc, args.username, password, args.domain,
                       port=args.port, use_ssl=args.use_ssl)
    except Exception as e:
        print(f"Error: {e}")
        return 1

    try:
        users = get_users(conn, base_dn)
        groups = get_groups(conn, base_dn)
        computers = get_computers(conn, base_dn)
    except Exception as e:
        print(f"Error: could not search the domain: {e}")
        return 1
    finally:
        conn.unbind()

    users_by_dn = {u["dn"]: u["sam"] for u in users if u["dn"]}
    privileged = get_privileged_members(groups, users_by_dn)
    findings = build_findings(users, privileged, args.stale_days)

    text = format_report(args.domain, args.dc, users, groups, privileged, computers, findings)
    print(text)
    write_text_report(args.output, text)
    print(f"Report saved to {args.output}")
    if args.csv:
        write_csv_report(args.csv, findings)
        print(f"CSV saved to {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
