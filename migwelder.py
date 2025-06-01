#!/usr/bin/python
"""AWS Mig Welder"""

import logging
import sys
from aws.discovery import Discovery

def generate_security_group(server_name):
    pass


def main():
    """main"""
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    # TODO: handle export servers
    # TODO: handle export connections
    # TODO: create security group 

    output_path = 'output'
    discovery = Discovery()
    discovery.export_server_inventory('output/servers.csv')
    discovery.export_network_connections('output/network_connections.json')


if __name__ == "__main__":
    main()
