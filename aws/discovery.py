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
