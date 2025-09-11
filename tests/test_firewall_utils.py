import csv
from migwelder.inventory import read_firewall_rules, check_firewall_rules


def test_read_firewall_rules(tmp_path):
    file = tmp_path / "fw.csv"
    with open(file, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "Name",
                "Source",
                "Destination",
                "FromPort",
                "ToPort",
                "Protocol",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "Name": "fw1",
                "Source": "10.0.0.0/16",
                "Destination": "192.168.1.0/24",
                "FromPort": "80",
                "ToPort": "80",
                "Protocol": "TCP",
            }
        )
    rules = read_firewall_rules(file)
    assert len(rules) == 1
    assert rules[0]["name"] == "fw1"
    assert str(rules[0]["src_net"]) == "10.0.0.0/16"
    assert str(rules[0]["dst_net"]) == "192.168.1.0/24"
    assert rules[0]["from_port"] == 80
    assert rules[0]["ip_protocol"] == "TCP"


def test_check_firewall_rules_match():
    fw_rules = [
        {
            "name": "fw1",
            "src_net": __import__("ipaddress").ip_network("10.0.0.0/16"),
            "dst_net": __import__("ipaddress").ip_network("192.168.1.0/24"),
            "from_port": 80,
            "to_port": 80,
            "ip_protocol": "TCP",
        }
    ]
    rule = {
        "Type": "ingress",
        "IpProtocol": "TCP",
        "FromPort": "80",
        "ToPort": "80",
        "CidrIp": "10.0.0.0/16",
    }
    ip_address = "192.168.1.0/24"
    result = check_firewall_rules(ip_address, rule, fw_rules)
    assert result == "fw1"


def test_check_firewall_rules_no_match():
    fw_rules = [
        {
            "name": "fw1",
            "src_net": __import__("ipaddress").ip_network("10.0.0.0/16"),
            "dst_net": __import__("ipaddress").ip_network("192.168.1.0/24"),
            "from_port": 80,
            "to_port": 80,
            "ip_protocol": "TCP",
        }
    ]
    rule = {
        "Type": "ingress",
        "IpProtocol": "TCP",
        "FromPort": "22",
        "ToPort": "22",
        "CidrIp": "10.0.0.0/16",
    }
    ip_address = "192.168.1.0/24"
    result = check_firewall_rules(ip_address, rule, fw_rules)
    assert result == "NO FIREWALL RULE FOUND"
