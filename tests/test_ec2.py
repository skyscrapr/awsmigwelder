import csv
from unittest.mock import patch, MagicMock
from aws.ec2 import EC2


@patch("boto3.client")
def test_export_security_group_rules(mock_boto_client, tmp_path):
    # Simulate describe_security_groups response
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [
                            {"CidrIp": "203.0.113.0/24", "Description": "SSH access"}
                        ],
                    }
                ],
                "IpPermissionsEgress": [
                    {
                        "IpProtocol": "-1",
                        "FromPort": None,
                        "ToPort": None,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0", "Description": "Allow all"}
                        ],
                    }
                ],
            }
        ]
    }
    mock_boto_client.return_value = mock_ec2

    output_file = tmp_path / "sg_rules.csv"
    ec2 = EC2()
    ec2.export_security_group_rules("sg-123456", str(output_file))

    # Validate CSV content
    assert output_file.exists()
    with open(output_file) as f:
        rows = list(csv.DictReader(f))
        assert len(rows) == 2

        ingress = next(r for r in rows if r["Type"] == "ingress")
        assert ingress["IpProtocol"] == "tcp"
        assert ingress["FromPort"] == "22"
        assert ingress["ToPort"] == "22"
        assert ingress["CidrIp"] == "203.0.113.0/24"
        assert ingress["Description"] == "SSH access"

        egress = next(r for r in rows if r["Type"] == "egress")
        assert egress["IpProtocol"] == "-1"
        assert egress["CidrIp"] == "0.0.0.0/0"
        assert egress["Description"] == "Allow all"
