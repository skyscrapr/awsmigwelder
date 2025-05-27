#!/usr/bin/python
"""AWS Mig Welder"""

import logging
import sys
from aws.discovery import Discovery

def main():
    """main"""
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    output_path = 'output'
    discovery = Discovery()
    discovery.export_server_inventory('output/servers.csv')
    # discovery.export_network_connections('output/network_connections.csv')
    print(f"Export completed to {output_path}")


if __name__ == "__main__":
    main()
