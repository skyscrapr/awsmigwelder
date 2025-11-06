"""discovery"""

import logging
import csv
import boto3
import requests
import botocore.auth
import botocore.awsrequest
import botocore.session
import json


LOGGER = logging.getLogger(__name__)


class Discovery:
    """Discovery"""

    def set_profile(self, profile):
        self.session = botocore.session.Session(profile=profile)
        self._aws_region = self.session.get_config_variable("region")
        if not self._aws_region:
            raise EnvironmentError("AWS region not set in profile.")

        # Resolve account ID once
        self._aws_account_id = ""
        try:
            # Use boto3 Session with the same botocore session
            b3 = boto3.session.Session(botocore_session=self.session)
            sts = b3.client("sts")
            ident = sts.get_caller_identity()
            self._aws_account_id = ident["Account"]
        except Exception as e:
            LOGGER.warning(
                f"Could not resolve AWS Account ID via STS for profile {profile}: {e}"
            )

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
        # Use the session tied to the selected profile
        credentials = self.session.get_credentials().get_frozen_credentials()
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
            account_id = self._aws_account_id

            print(
                f"⚠️ DestinationId: {destination_id} | Hostname: {hostname} | Account: {account_id}"
            )

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
                        "Ipv4Addresses": dest_node.get("Attributes", {}).get("ipv4Addresses", {}).get("SS", []),
                        "Type": "ingress" if ingress else "egress",
                        "IpProtocol": edge.get("Protocol", "tcp"),
                        "FromPort": port,
                        "ToPort": port,
                        "CidrIp": (
                            f"{source_node.get('Attributes', {}).get('ipv4Addresses', {}).get('SS', [''])[0]}/32"
                            if ingress
                            else f"{target_node.get('Attributes', {}).get('ipv4Addresses', {}).get('SS', [''])[0]}/32"
                        ),
                        "Description": (
                            source_node.get("Attributes", {}).get("hostname", {}).get("S", "")
                            if ingress
                            else target_node.get("Attributes", {}).get("hostname", {}).get("S", "")
                        ),
                    }
                    rules.append(rule)

            # Write to CSV
            with open(output_path, "w", newline="") as csvfile:
                fieldnames = [
                    "AccountId",
                    "Hostname",
                    "Ipv4Addresses",
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
            return True

        else:
            print(f"❌ Request failed with status {response.status_code}")
            print(response.text)
