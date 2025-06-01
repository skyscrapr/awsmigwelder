#!/usr/bin/python
"""AWS Mig Welder"""

import argparse
import logging
import sys
from aws.discovery import Discovery

def generate_security_group(server_name):
    pass


def main():
    """main"""
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    parser = argparse.ArgumentParser(
        description="Migration Utilities"
    )
    parser.add_argument(
        "--server_sg",
        type=str,
        help="The server id from AWS Migration Hub to generate an ingress security group for."
    )
    
    args = parser.parse_args()

    # TODO: handle export servers
    # TODO: handle export connections

    output_path = 'output'
    discovery = Discovery()
    # discovery.export_server_inventory('output/servers.csv')
    # discovery.export_network_connections('output/network_connections.json')
    discovery.export_security_group_rules(args.server_sg, "output/" + args.server_sg + ".csv")


if __name__ == "__main__":
    main()
