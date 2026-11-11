import csv


def format_report(domain, dc, users, groups, privileged, computers, findings):
    lines = []
    lines.append("ADEnum Report")
    lines.append(f"Domain: {domain}")
    lines.append(f"Domain controller: {dc}")
    lines.append("")
    lines.append(f"Users: {len(users)}")
    lines.append(f"Groups: {len(groups)}")
    lines.append(f"Computers: {len(computers)}")
    lines.append(f"Findings: {len(findings)}")
    lines.append("")
    lines.append("Privileged groups:")
    for group, members in privileged.items():
        lines.append(f"  {group} ({len(members)}): {', '.join(members) if members else 'none'}")
    lines.append("")
    if computers:
        lines.append("Computers:")
        for c in computers:
            lines.append(f"  {c['name']} — {c['os']}")
        lines.append("")
    lines.append("Findings:")
    order = {"High": 0, "Medium": 1, "Low": 2}
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 3)):
        lines.append(f"  [{f['severity']}] {f['account']} — {f['finding']}")
        lines.append(f"      {f['detail']}")
    if not findings:
        lines.append("  No findings.")
    return "\n".join(lines) + "\n"


def write_text_report(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def write_csv_report(path, findings):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["severity", "account", "finding", "detail"])
        for finding in findings:
            writer.writerow([finding["severity"], finding["account"],
                             finding["finding"], finding["detail"]])
