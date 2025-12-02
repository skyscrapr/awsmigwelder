import pytest
from pathlib import Path
from migwelder.inventory import read_rules_from_csv, preprocess_rules, get_network_rule

def test_read_rules_bom_and_headers(tmp_path):
    p = tmp_path / "rules.csv"
    # write BOM at start
    content = "\ufeffName,Source,Destination,Protocol,FromPort,ToPort\nMyRule,VMC_.*,AWS_.*,ALL,,\n"
    p.write_text(content, encoding="utf-8")
    rows = read_rules_from_csv(str(p))
    assert rows, "No rows read"
    assert "Name" in rows[0]
    assert rows[0]["Name"] == "MyRule"

def test_regex_matching_and_ports():
    raw = [
        {"Name": "VMC_to_AWS", "Source": "VMC_.*", "Destination": "AWS_.*", "Protocol": "ALL", "FromPort": "", "ToPort": ""},
        {"Name": "AWS_to_VMC", "Source": "AWS_.*", "Destination": "VMC_.*", "Protocol": "ALL", "FromPort": "", "ToPort": ""}
    ]
    proc = preprocess_rules(raw)
    flow = {"SrcNet": "VMC_1", "DstNet": "AWS_2", "FromPort": "100", "ToPort": "200", "IpProtocol": "ALL"}
    assert get_network_rule(None, flow, proc) == "VMC_to_AWS"

def test_port_range_matching():
    raw = [
        {"Name": "SpecificRange", "Source": "SRC_.*", "Destination": "DST_.*", "Protocol": "TCP", "FromPort": "1000", "ToPort": "2000"},
    ]
    proc = preprocess_rules(raw)
    flow_ok = {"SrcNet": "SRC_1", "DstNet": "DST_1", "FromPort": "1500", "ToPort": "1500", "IpProtocol": "TCP"}
    flow_no = {"SrcNet": "SRC_1", "DstNet": "DST_1", "FromPort": "2001", "ToPort": "2001", "IpProtocol": "TCP"}
    assert get_network_rule(None, flow_ok, proc) == "SpecificRange"
    assert get_network_rule(None, flow_no, proc) == "NO_RULE_FOUND"