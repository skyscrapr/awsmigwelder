#!/usr/bin/python
"""AWS Mig Welder"""

import argparse
import ipaddress
import logging
from pathlib import Path
import sys
import csv
from aws.discovery import Discovery
from typing import List, Dict, Tuple


LOGGER = logging.getLogger(__name__)


def process_inventory(discovery, input_file, output_path, known_networks, default_rules):
    """
    Process inventory

    For a given inventory
    1. export MGN server network data.
    2. enrich rules with network information.
    3. apply defaults and exclusions.
    4. create aggregated output.
    """
    # --- Read server IDs from CSV ---
    server_ids = []
    with open(input_file, 'r', newline='') as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            sid = (row.get('MGNServerID') or '').strip()
            if not sid:
                LOGGER.warning(f"Row {idx}: missing MGNServerID, skipping")
                continue
            server_ids.append(sid)

    # De-duplicate while preserving order
    seen = set()
    server_ids = [s for s in server_ids if not (s in seen or seen.add(s))]

    if not server_ids:
        raise ValueError("No MGNServerID values found in input CSV.")

    out = Path(output_path)
    out.mkdir(parents=True, exist_ok=True)

    out_raw = out / f"1-Raw"
    out_raw.mkdir(parents=True, exist_ok=True)

    out_enriched = out / f"2-Enriched"
    out_enriched.mkdir(parents=True, exist_ok=True)

    out_processed = out / f"3-Processed"
    out_processed.mkdir(parents=True, exist_ok=True)
    
    # Single, aggregated file
    aggregate_csv = out / "all_rules.csv"
    preferred = [
        "ServerId", "AccountId", "Hostname",
        "Type", "IpProtocol", "FromPort", "ToPort",
        "CidrIp", "Description"
    ]

    for server_id in server_ids:
        print(f"server: {server_id}")
        raw_file = out_raw / f"{server_id}.csv"
        discovery.export_mgn_server_network_data(server_id, str(raw_file))

        enriched_file = out_enriched / f"{server_id}.csv"
        rules = overlay_rules(raw_file, known_networks, str(enriched_file))

        processed_file = out_processed / f"{server_id}.csv"
        override_rules(enriched_file, default_rules, str(processed_file))

        append_rules_to_csv(
            output_csv=aggregate_csv,
            rows=rules or [],
            extra_cols={"ServerId": server_id},
            preferred_order=preferred
        )


def overlay_rules(input_file, rules_file, output_file):
    input_rules = read_rules_from_csv(input_file)
    new_rules = input_rules
    if rules_file:
        overlay_rules = load_rules(rules_file)
        new_rules = [remap_cidr(r, overlay_rules) for r in new_rules]
        new_rules = deduplicate_rules(new_rules)
    new_rules = consolidate_rules(new_rules)
    write_rules_to_csv(output_file, new_rules)
    return new_rules


def override_rules(input_file, rules_file, output_file):
    input_rules = read_rules_from_csv(input_file)
    override_rules = read_rules_from_csv(rules_file) if rules_file else []

    account_id = next((r.get("AccountId") for r in input_rules if r.get("AccountId")), "")
    hostname   = next((r.get("Hostname")   for r in input_rules if r.get("Hostname")),   "")

    for r in override_rules:
        r.setdefault("AccountId", account_id)
        r.setdefault("Hostname",   hostname)

    new_rules = override_rules + input_rules
    new_rules = deduplicate_rules(new_rules)
    write_rules_to_csv(output_file, new_rules)
    return new_rules


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
    fieldnames = ["AccountId", "Hostname", "Type", "IpProtocol", "FromPort", "ToPort", "CidrIp", "Description"]
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


def load_rules(
    path: str,
) -> List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    import csv

    rules = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                net = ipaddress.ip_network(row["CidrIp"].strip())
                desc = row.get("Description", "").strip()
                rules.append((net, desc))
            except ValueError:
                continue
    return rules


def remap_cidr(
    rule: dict, known_networks: List[Tuple[ipaddress._BaseNetwork, str]]
) -> dict:
    try:
        cidr = ipaddress.ip_network(rule["CidrIp"])
        for network, description in known_networks:
            if (
                isinstance(network, ipaddress.IPv4Network)
                and isinstance(cidr, ipaddress.IPv4Network)
                and cidr.subnet_of(network)
            ) or (
                isinstance(network, ipaddress.IPv6Network)
                and isinstance(cidr, ipaddress.IPv6Network)
                and cidr.subnet_of(network)
            ):
                rule["CidrIp"] = str(network)
                if description:
                    rule["Description"] = description
                break
    except ValueError:
        pass
    return rule


def append_rules_to_csv(output_csv, rows, extra_cols=None, preferred_order=None):
    """
    Append rows (list[dict]) to output_csv.
    - Writes header once (creates file if missing).
    - Ensures a stable column order (preferred_order first, then any others).
    - Fills missing keys with "".
    - extra_cols (dict) is merged into every row (e.g., {"ServerId": "..."}).
    """
    from pathlib import Path
    import csv

    output_csv = Path(output_csv)
    exists = output_csv.exists()

    # Merge extras
    if extra_cols:
        rows = [{**r, **extra_cols} for r in rows]

    if not rows:
        return  # nothing to append

    # Determine fieldnames
    if exists:
        # Reuse existing header
        with output_csv.open("r", newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader, None)
        fieldnames = header if header else list(rows[0].keys())
    else:
        # Build union of keys across incoming rows
        seen = set()
        union = []
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    union.append(k); seen.add(k)
        # Put preferred columns first if provided
        if preferred_order:
            fieldnames = [c for c in preferred_order if c in union] + [c for c in union if c not in preferred_order]
        else:
            fieldnames = union

    # Append/write
    with output_csv.open("a" if exists else "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})


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
        "export-mgn-server-network-data", help="Export MGN server discovery network data"
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

    # Subcommand: overlay_rules
    consolidate_parser = subparsers.add_parser(
        "overlay_rules", help="Overlay rules and consolidate CIDRs."
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
        "process-inventory", help="Process a given inventory. Export the MGN data, enrich with known networks and apply defaults"
    )
    sd_parser.add_argument(
        "-i", "--input", required=True, help="The inventory of servers to export."
    )
    sd_parser.add_argument(
        "-o",
        "--output",
        required=True,
        help="The folder path to write the output files to.",
    )
    sd_parser.add_argument(
        "-k", "--known-networks", required=True, help="known networks to overlay"
    )
    sd_parser.add_argument(
        "-d", "--default-rules", required=True, help="default rules to apply"
    )


    args = parser.parse_args()

    discovery = Discovery()
    if args.command == "process-inventory":
        process_inventory(discovery, args.input, args.output, args.known_networks, args.default_rules)
    elif args.command == "export-mgn-server":    
        discovery.export_mgn_server_network_data(args.id, args.output)
    elif args.command == "overlay_rules":
        overlay_rules(args.input, args.rules, args.output)


if __name__ == "__main__":
    main()
