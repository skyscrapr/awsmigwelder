from migwelder import (
    is_covered,
    consolidate_rules,
    write_rules_to_csv,
    read_rules_from_csv,
)

sample_rules = [
    {
        "Type": "ingress",
        "IpProtocol": "tcp",
        "FromPort": "80",
        "ToPort": "80",
        "CidrIp": "10.0.0.0/24",
        "Description": "HTTP",
    },
    {
        "Type": "ingress",
        "IpProtocol": "tcp",
        "FromPort": "80",
        "ToPort": "80",
        "CidrIp": "10.0.0.10/32",
        "Description": "Specific Host",
    },
    {
        "Type": "egress",
        "IpProtocol": "-1",
        "FromPort": "",
        "ToPort": "",
        "CidrIp": "0.0.0.0/0",
        "Description": "All outbound",
    },
]


def test_is_covered_true():
    assert is_covered(sample_rules[0], sample_rules[1]) is True


def test_is_covered_false_type():
    assert not is_covered(sample_rules[0], sample_rules[2])


def test_consolidate_rules():
    consolidated = consolidate_rules(sample_rules)
    assert len(consolidated) == 2  # second rule is covered by the first


def test_csv_roundtrip(tmp_path):
    test_file = tmp_path / "rules.csv"
    write_rules_to_csv(test_file, sample_rules)
    read_back = read_rules_from_csv(test_file)
    assert read_back == sample_rules
