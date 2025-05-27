""" discovery """
import logging
import boto3
import csv
import time
import requests
import zipfile


LOGGER = logging.getLogger(__name__)


class Discovery:
    """ Discovery """

    def export_network_connections(self, output_path):
        client = boto3.client('discovery')

        server_paginator = client.get_paginator('list_configurations')
        server_page_iterator = server_paginator.paginate(
            configurationType='SERVER'
        )

        first_row = True
        with open(output_path, mode='w', newline='') as out_file:
            for config_page in server_page_iterator:
                for config in config_page['configurations']:
                    response = client.list_server_neighbors(configurationId=config['server.configurationId'])
                    if not response.get('neighbors'):
                        print(f"No neighbors for: {config['server.configurationId']}")

                    for neighbor in response.get('neighbors', []):
                        if first_row:
                            fieldnames = list(neighbor.keys())
                            writer = csv.DictWriter(out_file, fieldnames=fieldnames)
                            writer.writeheader()
                            first_row = False
                        writer.writerow(neighbor)               

        print("✅ File created: {output_path}")
                                   

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
