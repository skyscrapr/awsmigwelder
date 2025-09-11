import csv
from migwelder import inventory


def test_apply_exclusions_basic(tmp_path):
    # Prepare input CSV
    input_file = tmp_path / "input.csv"
    output_file = tmp_path / "output.csv"
    rows = [
        {"CidrIp": "10.0.0.0/24", "Other": "a"},
        {"CidrIp": "10.0.1.0/24", "Other": "b"},
        {"CidrIp": "192.168.1.0/24", "Other": "c"},
    ]
    with open(input_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["CidrIp", "Other"])
        writer.writeheader()
        writer.writerows(rows)

    # Exclude one CIDR
    inventory.apply_exclusions(str(input_file), ["10.0.1.0/24"], str(output_file))
    with open(output_file) as f:
        out_rows = list(csv.DictReader(f))
    assert len(out_rows) == 2
    assert all(r["CidrIp"] != "10.0.1.0/24" for r in out_rows)


def test_deduplicate_rules():
    rules = [
        {
            "Type": "ingress",
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "10.0.0.0/24",
            "Description": "web",
        },
        {
            "Type": "ingress",
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "10.0.0.0/24",
            "Description": "web",
        },
        {
            "Type": "egress",
            "IpProtocol": "udp",
            "FromPort": "53",
            "ToPort": "53",
            "CidrIp": "8.8.8.8/32",
            "Description": "dns",
        },
    ]
    deduped = inventory.deduplicate_rules(rules)
    assert len(deduped) == 2
    assert any(r["Type"] == "egress" for r in deduped)


def test_consolidate_rules():
    rules = [
        {
            "Type": "ingress",
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "10.0.0.0/24",
            "Description": "web",
        },
        {
            "Type": "ingress",
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "10.0.0.0/24",
            "Description": "web",
        },
        {
            "Type": "ingress",
            "IpProtocol": "tcp",
            "FromPort": "80",
            "ToPort": "80",
            "CidrIp": "10.0.0.0/16",
            "Description": "bigger",
        },
    ]
    consolidated = inventory.consolidate_rules(rules)
    # Only the broader rule should remain
    assert any(r["CidrIp"] == "10.0.0.0/16" for r in consolidated)
    assert not any(r["CidrIp"] == "10.0.0.0/24" for r in consolidated)


def test_is_covered():
    broader = {
        "Type": "ingress",
        "IpProtocol": "tcp",
        "FromPort": "80",
        "ToPort": "80",
        "CidrIp": "10.0.0.0/16",
    }
    specific = {
        "Type": "ingress",
        "IpProtocol": "tcp",
        "FromPort": "80",
        "ToPort": "80",
        "CidrIp": "10.0.0.0/24",
    }
    assert inventory.is_covered(broader, specific)
    assert not inventory.is_covered(specific, broader)


def test_remap_cidr():
    rule = {"CidrIp": "10.0.1.0/24"}
    known_networks = [(inventory.ipaddress.ip_network("10.0.0.0/16"), "desc")]
    remapped = inventory.remap_cidr(rule.copy(), known_networks)
    assert remapped["CidrIp"] == "10.0.0.0/16"
    assert remapped["Description"] == "desc"


def test_combine_csv_files(tmp_path):
    d = tmp_path / "csvs"
    d.mkdir()
    f1 = d / "a.csv"
    f2 = d / "b.csv"
    with open(f1, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["CidrIp", "Other"])
        writer.writeheader()
        writer.writerow({"CidrIp": "1.1.1.1/32", "Other": "x"})
    with open(f2, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["CidrIp", "Other"])
        writer.writeheader()
        writer.writerow({"CidrIp": "2.2.2.2/32", "Other": "y"})
    out = tmp_path / "out.csv"
    inventory.combine_csv_files(d, out)
    with open(out) as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert {r["CidrIp"] for r in rows} == {"1.1.1.1/32", "2.2.2.2/32"}
