#!/usr/bin/python
"""AWS Mig Welder"""

import argparse
import ipaddress
import logging
import sys
import csv
from aws.discovery import Discovery
from aws.ec2 import EC2
from typing import Any, List, Dict, Tuple


# def parse_rule(row: Dict[str, str]) -> Tuple:
#     """Normalize rule fields to a hashable tuple key."""
#     def safe_int(value):
#         try:
#             return int(value)
#         except (ValueError, TypeError):
#             return None

#     fromPort = row["FromPort"] or ""
#     fromPort = safe_int(fromPort)

#     toPort = row["ToPort"] or ""
#     toPort = safe_int(toPort)

#     return (
#         row["Type"].strip().lower(),
#         row["IpProtocol"].strip().lower(),
#         fromPort,
#         toPort,
#         row["CidrIp"].strip().lower(),
#     )


def read_rules_from_csv(file_path: str) -> List[Dict[str, str]]:
    """Read security rules from a CSV file into a list of dictionaries."""
    with open(file_path, mode="r", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def deduplicate_rules(rules: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    unique_rules = []
    for rule in rules:
        # Convert to a hashable tuple of relevant fields
        key = (
            rule["Type"].lower(),
            rule["IpProtocol"].lower(),
            str(rule.get("FromPort", "")).strip(),
            str(rule.get("ToPort", "")).strip(),
            rule["CidrIp"].strip(),
            rule.get("Description", "").strip().lower(),
        )
        if key not in seen:
            seen.add(key)
            unique_rules.append(rule)
    return unique_rules


def consolidate_rules(rules: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Consolidate Rules."""
    consolidated = []

    for i, i_rule in enumerate(rules):
        covered = False
        for j, j_rule in enumerate(rules):
            if i == j:
                continue  # don't compare a rule against itself
            if is_covered(j_rule, i_rule):
                covered = True
                break
        if not covered:
            consolidated.append(i_rule)

    return consolidated


def write_rules_to_csv(file_path: str, rules: List[Dict[str, str]]) -> None:
    """Write consolidated rules to a CSV file."""
    fieldnames = ["Type", "IpProtocol", "FromPort", "ToPort", "CidrIp", "Description"]
    with open(file_path, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rule in rules:
            writer.writerow(rule)


def is_covered(broader: dict, specific: dict) -> bool:
    # Type (ingress/egress) must match
    if broader["Type"] != specific["Type"]:
        return False

    # Protocol match: '-1' covers all, otherwise must match exactly
    if (
        broader["IpProtocol"] != "-1"
        and broader["IpProtocol"] != specific["IpProtocol"]
    ):
        return False

    # Port range check (only for non '-1' protocols)
    if broader["IpProtocol"] != "-1":
        try:
            b_from = int(broader.get("FromPort", ""))
            b_to = int(broader.get("ToPort", ""))
            s_from = int(specific.get("FromPort", ""))
            s_to = int(specific.get("ToPort", ""))
            if not (b_from <= s_from <= s_to <= b_to):
                return False
        except (ValueError, TypeError):
            return False

    # CIDR check: broader must fully contain specific
    try:
        b_net = ipaddress.ip_network(broader["CidrIp"])
        s_net = ipaddress.ip_network(specific["CidrIp"])

        if isinstance(s_net, ipaddress.IPv4Network) and isinstance(
            b_net, ipaddress.IPv4Network
        ):
            return s_net.subnet_of(b_net)
        elif isinstance(s_net, ipaddress.IPv6Network) and isinstance(
            b_net, ipaddress.IPv6Network
        ):
            btemp = s_net.subnet_of(b_net)
            if btemp:
                return True
            else:
                return False
        else:
            return False
    except ValueError:
        return False


def load_known_networks(path: str) -> List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    import csv

    known_networks = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                net = ipaddress.ip_network(row["CidrIp"].strip())
                desc = row.get("Description", "").strip()
                known_networks.append((net, desc))
            except ValueError:
                continue
    return known_networks


def remap_cidr(
    rule: dict, known_networks: List[Tuple[ipaddress._BaseNetwork, str]]
) -> dict:
    try:
        cidr = ipaddress.ip_network(rule["CidrIp"])
        for network, description in known_networks:
            if (isinstance(network, ipaddress.IPv4Network) and isinstance(cidr, ipaddress.IPv4Network) and cidr.subnet_of(network)) or (isinstance(network, ipaddress.IPv6Network) and isinstance(cidr, ipaddress.IPv6Network) and cidr.subnet_of(network)):
                rule["CidrIp"] = str(network)
                if description:
                    rule["Description"] = description
                break
    except ValueError:
        pass
    return rule


def main():
    """main"""
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="Migration Utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: export-sg-rules
    sg_parser = subparsers.add_parser(
        "export-sg-rules", help="Export security group rules"
    )
    sg_parser.add_argument(
        "-i", "--id", required=True, help="The security group ID to export rules from."
    )
    sg_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="The path and filename to write the output to.",
    )

    # Subcommand: export-server-sg-rules
    server_sg_parser = subparsers.add_parser(
        "export-server-sg-rules", help="Export server security group rules"
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

    # Subcommand: consolidate-sg-rules
    consolidate_parser = subparsers.add_parser(
        "consolidate-sg-rules", help="Export server security group rules."
    )
    consolidate_parser.add_argument(
        "-i", "--input", required=True, help="The server rules to consolidate."
    )
    consolidate_parser.add_argument(
        "-d", "--default", required=False, help="The default rules to add to the set."
    )
    consolidate_parser.add_argument(
        "-k",
        "--known-networks",
        required=False,
        help="Known networks to replace narrower ranges with.",
    )
    consolidate_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="The path and filename to write the output to.",
    )

    args = parser.parse_args()

    if args.command == "export-sg-rules":
        ec2 = EC2()
        ec2.export_security_group_rules(args.id, args.output)

    elif args.command == "export-server-sg-rules":
        discovery = Discovery()
        discovery.export_server_security_group_rules(args.id, args.output)

    elif args.command == "consolidate-sg-rules":
        input_rules = read_rules_from_csv(args.input)
        default_rules = read_rules_from_csv(args.default) if args.default else []
        new_rules = default_rules + input_rules
        new_rules = deduplicate_rules(new_rules)
        if args.known_networks:
            known_networks = load_known_networks(args.known_networks)
            new_rules = [remap_cidr(r, known_networks) for r in new_rules]
            new_rules = deduplicate_rules(new_rules)
        new_rules = consolidate_rules(new_rules)
        write_rules_to_csv(args.output, new_rules)


if __name__ == "__main__":
    main()
