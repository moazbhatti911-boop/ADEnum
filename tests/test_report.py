from adenum.report import format_report


def test_report_contains_findings():
    text = format_report("lab.local", "192.168.56.10", [{"sam": "alice"}], {"Domain Admins": {}},
                         {"Domain Admins": ["alice"]}, [],
                         [{"severity": "High", "account": "alice",
                           "finding": "Member of Domain Admins", "detail": "x"}])
    assert "Domain Admins" in text
    assert "[High] alice" in text
