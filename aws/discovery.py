""" discovery """
import logging
import boto3
import csv
import requests
import botocore.auth
import botocore.awsrequest
import botocore.session
import json


LOGGER = logging.getLogger(__name__)


class Discovery:
    """ Discovery """

    def export_security_group_rules(self, server_id, output_path):
        # --- Configuration ---
        region = "us-east-1"
        service = "discovery"
        endpoint = "https://api.us-east-1.prod.adm.migrationhub.aws.a2z.com/"
        target = "AWSADMAPIService.GetNetworkConnectionGraph"
        payload = {
            "Resources": {
                "GetByServerIds": {
                    "ServerIds": [server_id]
                }
            }
        }
        headers = {
            "Content-Type": "application/x-amz-json-1.0",
            "X-Amz-Target": target,
        }

        # --- AWS SigV4 Signing ---
        session = botocore.session.get_session()
        credentials = session.get_credentials()
        request = botocore.awsrequest.AWSRequest(
            method="POST",
            url=endpoint,
            data=json.dumps(payload),
            headers=headers,
        )
        sigv4 = botocore.auth.SigV4Auth(credentials, service, region)
        sigv4.add_auth(request)

        # --- Send the request ---
        prepared_request = request.prepare()
        response = requests.post(
            prepared_request.url,
            headers=dict(prepared_request.headers),
            data=prepared_request.body,
        )

        # --- Output to file ---
        if response.ok:
            data = response.json()
            nodes = {node["Id"]: node for node in data.get("Nodes", [])}
            edges = data.get("Edges", [])

            # Find the ID for the target hostname
            destination_ids = [
                node_id for node_id, node in nodes.items()
                if node.get("Attributes", {}).get("serverId", {}).get("S") == server_id.lower()
            ]
            if not destination_ids:
                print(f"❌ No node found with serverId: {server_id}")
                exit(1)

            destination_id = destination_ids[0]
            print(f"⚠️ DestinationId: {destination_id}")

            if not edges:
                print("⚠️ No connections found for the specified host")
                exit(0)

            # Generate simplified ingress rule rows
            rules = []
            for edge in edges:
                source_node = nodes.get(edge.get("Source"))
                for port in edge.get("Attributes", {}).get("ports", {}).get("IS", ""): 
                    rule = {
                        "Type": "ingress" if edge.get("Target") == destination_id else "egress", 
                        "IpProtocol": edge.get("Protocol", "tcp"),
                        "FromPort": port,
                        "ToPort": port,
                        "CidrIp": f"{source_node.get('Attributes', {}).get('ipv4Addresses', {}).get('SS', [''])[0]}/32",
                        "Description": source_node.get("Attributes", {}).get("hostname", {}).get("S", "")               
                    }
                    rules.append(rule)

            # Write to CSV
            with open(output_path, "w", newline="") as csvfile:
                fieldnames = ["Type", "IpProtocol", "FromPort", "ToPort", "CidrIp", "Description"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rules)

            print(f"✅ Rules exported to {output_path}")

        else:
            print(f"❌ Request failed with status {response.status_code}")
            print(response.text)


    def export_network_connections(self, output_path):
        # --- Configuration ---
        region = "us-east-1"
        service = "discovery"
        endpoint = "https://api.us-east-1.prod.adm.migrationhub.aws.a2z.com/"
        target = "AWSADMAPIService.GetNetworkConnectionGraph"
        payload = {
            "Resources": {
                "GetByServerIds": {
                    "ServerIds": ["d-server-038oarq94eqr96"]
                }
            }
        }
        headers = {
            "Content-Type": "application/x-amz-json-1.0",
            "X-Amz-Target": target,
        }

        # --- AWS SigV4 Signing ---
        session = botocore.session.get_session()
        credentials = session.get_credentials()
        request = botocore.awsrequest.AWSRequest(
            method="POST",
            url=endpoint,
            data=json.dumps(payload),
            headers=headers,
        )
        sigv4 = botocore.auth.SigV4Auth(credentials, service, region)
        sigv4.add_auth(request)

        # --- Send the request ---
        prepared_request = request.prepare()
        response = requests.post(
            prepared_request.url,
            headers=dict(prepared_request.headers),
            data=prepared_request.body,
        )

        # --- Output to file ---
        if response.ok:
            data = response.json()
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
            print(f"✅ Network graph data saved to {output_path}")

                # Extract edges from response
            # Assumes format like: {"Graph": {"Edges": [{"SourceId": "x", "DestinationId": "y", ...}]}}
            edges = data.get("Graph", {}).get("Edges", [])

            if edges:
                with open(output_csv_file, "w", newline="") as csvfile:
                    fieldnames = edges[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(edges)
                print(f"✅ CSV data saved to {output_csv_file}")
            else:
                print("⚠️ No edges found in network graph")
        else:
            print(f"❌ Request failed with status {response.status_code}")
            print(response.text)
                                   

    def export_server_inventory(self, output_path):
        client = boto3.client('discovery')

        paginator = client.get_paginator('list_configurations')
        page_iterator = paginator.paginate(
            configurationType='SERVER'
        )

        first_row = True
        with open(output_path, mode='w', newline='') as out_file:
            for page in page_iterator:
                for config in page['configurations']:
                    if first_row:
                        fieldnames = list(config.keys())
                        writer = csv.DictWriter(out_file, fieldnames=fieldnames)
                        writer.writeheader()
                        first_row = False
                    writer.writerow(config)
    
        print("✅ File created: {output_path}")
