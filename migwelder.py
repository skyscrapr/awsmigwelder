#!/usr/bin/python
"""AWS Mig Welder"""

import argparse
import logging
import sys
from aws.discovery import Discovery
from aws.ec2 import EC2


def main():
    """main"""
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    parser = argparse.ArgumentParser(description="Migration Utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: export-sg
    sg_parser = subparsers.add_parser("export-sg", help="Export security group rules")
    sg_parser.add_argument(
        "--id", required=True,
        help="The security group ID to export rules from."
    )

    # Subcommand: export-server-sg
    server_sg_parser = subparsers.add_parser("export-server-sg", help="Export server security group")
    server_sg_parser.add_argument(
        "--id", required=True,
        help="The server ID from AWS migration hub to create the security group for."
        # "--output", default="output/servers.csv",
        # help="Output file for server export"
    )
    
    args = parser.parse_args()

    if args.command == "export-server-sg":
        discovery = Discovery()
        discovery.export_security_group_rules(args.id, args.id + ".csv")

    elif args.command == "export-sg":
        ec2 = EC2()
        ec2.export_security_group_rules(args.id, args.id + ".csv")

    # TODO: discovery.export_server_inventory('output/servers.csv')
    # TODO: discovery.export_network_connections('output/network_connections.json')

if __name__ == "__main__":
    main()
