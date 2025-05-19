""" discovery """
import logging
import boto3
import csv

LOGGER = logging.getLogger(__name__)


class Discovery:
    """ Utils """

    def export_network_connections(self, output_file):
        client = boto3.client('discovery')

        # Get list of all discovered servers
        servers = client.list_configurations(configurationType='SERVER')
        server_ids = [s['configurationId'] for s in servers['configurations']]

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
            