import csv
from unittest.mock import patch, MagicMock
from aws.discovery import Discovery


def fake_mh_response(server_id):
    return {
        "Nodes": [
            {
                "Id": "node-123",
                "Attributes": {
                    "serverId": {"S": server_id.lower()},
                    "ipv4Addresses": {"SS": ["10.0.0.5"]},
                    "hostname": {"S": "example-host.local"},
                },
            },
            {
                "Id": "node-456",
                "Attributes": {
                    "ipv4Addresses": {"SS": ["10.0.0.10"]},
                    "hostname": {"S": "external-host.local"},
                },
            },
        ],
        "Edges": [
            {
                "Source": "node-456",
                "Target": "node-123",
                "Protocol": "tcp",
                "Attributes": {"ports": {"IS": [443]}},
            }
        ],
    }


@patch("aws.discovery.requests.post")
@patch("botocore.session.get_session")
def test_export_server_security_group_rules(mock_session, mock_post, tmp_path):
    # Setup mocks
    creds = MagicMock()
    creds.access_key = "ak"
    creds.secret_key = "sk"
    creds.token = "tok"

    mock_session.return_value.get_credentials.return_value = creds

    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.json.return_value = fake_mh_response("d-server-123")
    mock_post.return_value = mock_response

    output_file = tmp_path / "rules.csv"

    # Run the method
    d = Discovery()
    d.export_server_security_group_rules("d-server-123", str(output_file), "us-east-1")

    # Assert output CSV exists and has expected content
    assert output_file.exists()

    with open(output_file) as f:
        rows = list(csv.DictReader(f))
        assert len(rows) == 1
        assert rows[0]["CidrIp"] == "10.0.0.10/32"
        assert rows[0]["FromPort"] == "443"
        assert rows[0]["Type"] == "ingress"


@patch("boto3.client")
def test_export_server_inventory(mock_boto_client, tmp_path):
    mock_client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"configurations": [{"hostName": "srv01", "ip": "10.1.2.3"}]}
    ]
    mock_client.get_paginator.return_value = paginator
    mock_boto_client.return_value = mock_client

    output_file = tmp_path / "inventory.csv"

    d = Discovery()
    d.export_server_inventory(str(output_file))

    assert output_file.exists()

    with open(output_file) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["hostName"] == "srv01"
