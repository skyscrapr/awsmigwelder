"""discovery"""

import logging
import os
from pathlib import Path
import csv
import requests
import botocore.auth
import botocore.awsrequest
import botocore.session
import json


LOGGER = logging.getLogger(__name__)


class Discovery:
    """Discovery"""

    def __init__(self):
        self._aws_region = os.getenv("AWS_REGION")
        if not self._aws_region:
            raise EnvironmentError("AWS_REGION environment variable is not set.")


    def export_mgn_servers(self, input_file, output_path):
        """
        Export MGN server network data for a list of servers in input CSV.
        This will write one CSV per server into that directory specified.
        """
        # --- Read server IDs from CSV ---
        server_ids = []
        with open(input_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=1):
                sid = (row.get('MGNServerID') or '').strip()
                if not sid:
                    LOGGER.warning(f"Row {idx}: missing MGNServerID, skipping")
                    continue
                server_ids.append(sid)

        # De-duplicate while preserving order
        seen = set()
        server_ids = [s for s in server_ids if not (s in seen or seen.add(s))]

        if not server_ids:
            raise ValueError("No MGNServerID values found in input CSV.")

        out = Path(output_path)
        out.mkdir(parents=True, exist_ok=True)
        for server_id in server_ids:
            print(f"server: {server_id}")
            per_file = out / f"{server_id}.csv"
            self.export_mgn_server_network_data(server_id, str(per_file))


    def export_mgn_server_network_data(self, server_id, output_path):
        # --- Configuration ---
        service = "discovery"
        endpoint = f"https://api.{self._aws_region}.prod.adm.migrationhub.aws.a2z.com/"
        target = "AWSADMAPIService.GetNetworkConnectionGraph"
        payload = {"Resources": {"GetByServerIds": {"ServerIds": [server_id]}}}
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
        sigv4 = botocore.auth.SigV4Auth(credentials, service, self._aws_region)
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
                node_id
                for node_id, node in nodes.items()
                if node.get("Attributes", {}).get("serverId", {}).get("S")
                == server_id.lower()
            ]
            if not destination_ids:
                print(f"❌ No node found with serverId: {server_id}")
                return

            destination_id = destination_ids[0]
            dest_node = nodes[destination_id]

            hostname = dest_node.get("Attributes", {}).get("hostname", {}).get("S", "")
            account_id = ""
            try:
                sts = session.create_client("sts", region_name=self._aws_region)
                account_id = sts.get_caller_identity()["Account"]
            except Exception as e:
                LOGGER.warning(f"Could not resolve AWS Account ID via STS: {e}")
            
            print(f"⚠️ DestinationId: {destination_id} | Hostname: {hostname} | Account: {account_id}")

            if not edges:
                print("⚠️ No connections found for the specified host")
                return

            # Generate simplified ingress rule rows
            rules = []
            for edge in edges:
                source_node = nodes.get(edge.get("Source"))
                target_node = nodes.get(edge.get("Target"))
                for port in edge.get("Attributes", {}).get("ports", {}).get("IS", []):
                    ingress = edge.get("Target") == destination_id

                    rule = {
                        "AccountId": account_id,
                        "Hostname": hostname,
                        "Type": "ingress" if ingress else "egress",
                        "IpProtocol": edge.get("Protocol", "tcp"),
                        "FromPort": port,
                        "ToPort": port,
                        "CidrIp": f"{source_node.get('Attributes', {}).get('ipv4Addresses', {}).get('SS', [''])[0]}/32",
                        "Description": (
                            source_node.get("Attributes", {}).get("hostname", {}).get("S", "")
                            if ingress else target_node.get("Attributes", {}).get("hostname", {}).get("S", "")
                        )
                    }
                    rules.append(rule)

            # Write to CSV
            with open(output_path, "w", newline="") as csvfile:
                fieldnames = [
                    "AccountId",
                    "Hostname",
                    "Type",
                    "IpProtocol",
                    "FromPort",
                    "ToPort",
                    "CidrIp",
                    "Description",
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rules)

            print(f"✅ Rules exported to {output_path}")

        else:
            print(f"❌ Request failed with status {response.status_code}")
            print(response.text)

