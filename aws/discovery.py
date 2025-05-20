""" discovery """
import logging
import boto3
import csv
import time
import requests
import zipfile


LOGGER = logging.getLogger(__name__)


class Discovery:
    """ Utils """

    def export_network_connections(self, output_file):
        client = boto3.client('discovery')

        # Get list of all discovered servers
        servers = client.list_configurations(configurationType='SERVER')
        server_ids = [s['server.configurationId'] for s in servers['configurations']]

        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['source', 'destination', 'protocol', 'port']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for server_id in server_ids:
                neighbors = client.list_server_neighbors(
                    configurationId=server_id,
                    neighborConfigurationType='SERVER',
                    maxResults=100
                )

                for neighbor in neighbors.get('neighbors', []):
                    writer.writerow({
                        'source': server_id,
                        'destination': neighbor['neighborConfigurationId'],
                        'protocol': neighbor.get('protocol', 'N/A'),
                        'port': neighbor.get('port', 'N/A')
                    })

    def export_ads_data(self, output_path):
        client = boto3.client('discovery')

        # Start export task
        print("Starting export task...")
        response = client.start_export_task(exportDataFormat=['CSV'])
        task_id = response['exportId']

        # Wait for completion
        print(f"Waiting for export task {task_id} to complete...")
        while True:
            export_status = client.describe_export_tasks(exportIds=[task_id])
            status = export_status['exportsInfo'][0]['exportStatus']
            if status == 'SUCCEEDED':
                break
            elif status == 'FAILED':
                raise Exception("Export task failed.")
            time.sleep(5)

        # Get URL
        url = export_status['exportsInfo'][0]['configurationsDownloadUrl']
        print(f"Export completed. Download CSV: {url}")

        # Download and convert the CSV
        
        import io

        print("Downloading exported data...")
        response = requests.get(url)
        response.raise_for_status()

       # Read ZIP content
        zip_bytes = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_bytes, 'r') as zip_file:
            # Assuming there's only one CSV file inside
            csv_filename = zip_file.namelist()[0]
            with zip_file.open(csv_filename) as csv_file:
                decoded = csv_file.read().decode('utf-8')

        reader = csv.DictReader(io.StringIO(decoded, newline=''))

        output_fields = [
            'serverName', 'ipAddress', 'macAddress', 'osName', 'cpuCores',
            'cpuSpeed', 'ram', 'disks', 'agentId'
        ]

        with open(output_path, mode='w', newline='') as out_file:
            writer = csv.DictWriter(out_file, fieldnames=output_fields)
            writer.writeheader()

            for row in reader:
                writer.writerow({
                    'serverName': row.get('hostName', ''),
                    'ipAddress': row.get('ipAddress', ''),
                    'macAddress': row.get('macAddress', ''),
                    'osName': row.get('osVersion', ''),
                    'cpuCores': row.get('cpuCores', ''),
                    'cpuSpeed': row.get('cpuSpeed', ''),
                    'ram': row.get('ram', ''),
                    'disks': row.get('disks', ''),
                    'agentId': row.get('agentId', '')
                })

        print("✅ File created: {output_path}")