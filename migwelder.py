#!/usr/bin/python
"""AWS Mig Welder"""

import argparse
import logging
import sys
from aws.discovery import Discovery
from migwelder.inventory import Inventory, overlay_networks


LOGGER = logging.getLogger(__name__)


def main():
    """main"""
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="Migration Utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: export-mgn-server-network-data
    server_sg_parser = subparsers.add_parser(
        "export-mgn-server-network-data",
        help="Export MGN server discovery network data",
    )
    server_sg_parser.add_argument(
        "-i",
        "--id",
        required=True,
        help="The server ID from AWS migration hub to export the security group rules for.",
    )
    server_sg_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="The path and filename to write the output to.",
    )

    # Subcommand: overlay_networks
    consolidate_parser = subparsers.add_parser(
        "overlay_networks", help="Overlay rules and consolidate CIDRs."
    )
    consolidate_parser.add_argument(
        "-i", "--input", required=True, help="The rules to consolidate."
    )
    # consolidate_parser.add_argument(
    #     "-d", "--default", required=False, help="The default rules to add to the set."
    # )
    consolidate_parser.add_argument(
        "-r",
        "--rules",
        required=False,
        help="Rules to overlay CIDRs will be replace with wider ranges if matched.",
    )
    consolidate_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="The filename to write the output to.",
    )

    # Subcommand: process-inventory
    sd_parser = subparsers.add_parser(
        "process-inventory",
        help="Process a given inventory. Export the MGN data, enrich with known networks and apply defaults",
    )
    sd_parser.add_argument(
        "-i", "--inventory", required=True, help="The inventory of servers."
    )
    sd_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="The folder path to write the output files to.",
    )
    sd_parser.add_argument(
        "-n", "--networks", required=True, help="known networks to overlay"
    )
    sd_parser.add_argument(
        "-d", "--defaults", required=True, help="default rules to apply"
    )
    sd_parser.add_argument(
        "-e", "--exclusions", required=True, help="exclusions to apply"
    )
    sd_parser.add_argument(
        "-f", "--firewalls", required=True, help="firewall rules to verify"
    )

    args = parser.parse_args()

    discovery = Discovery()
    inventory = Inventory(discovery)
    if args.command == "process-inventory":
        inventory.load_inventory(args.inventory)
        inventory.process(
            args.output, args.exclusions, args.networks, args.firewalls, args.defaults
        )
    elif args.command == "export-mgn-server":
        discovery.export_mgn_server_network_data(args.id, args.output)
    elif args.command == "overlay_networks":
        overlay_networks(args.input, args.rules, args.output)


if __name__ == "__main__":
    main()
