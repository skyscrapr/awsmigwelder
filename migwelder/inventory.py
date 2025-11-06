import ipaddress
import csv
import re
from pathlib import Path
from typing import List, Dict, Tuple


class Inventory:
    """ Inventory """

    def __init__(self, discovery):
        self._discovery = discovery

    def load_inventory(self, file_path):
        self._inventory = []
        with open(file_path, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for idx, row in enumerate(reader, start=1):
                self._inventory.append(row)


    def process(self, output_path, exclusions, networks, rules, defaults):
        """
        Process inventory

        For a given inventory
        1. export MGN network data (1. Raw)
        2. apply exclusions to remove unnecessary data.
        3. enrich data with network information including source and target if known (2. Network)
        3. enrich data with rules matches (3. Rules)
        4. apply defaults and consolidate. (4. Consolidated)
        """

        out = Path(output_path)
        out_raw = out / f"1-Raw"
        out_source = out / f"2-Source"
        out_target = out / f"3-Target"
        out_consolidated = out / f"4-Consolidated"
        out.mkdir(parents=True, exist_ok=True)
        out_raw.mkdir(parents=True, exist_ok=True)
        out_source.mkdir(parents=True, exist_ok=True)  
        out_target.mkdir(parents=True, exist_ok=True)      
        out_consolidated.mkdir(parents=True, exist_ok=True)

        for server in self._inventory:
            server_id = server["MGNServerID"]
            hostname = server["Hostname"]
            aws_profile = server["AWSProfile"]
            self._discovery.set_profile(aws_profile)

            raw_file = out_raw / f"{hostname}-{server_id}.csv"
            if self._discovery.export_mgn_server_network_data(server_id, str(raw_file)):
                source_file = out_source / f"{hostname}-{server_id}.csv"
                target_file = out_target / f"{hostname}-{server_id}.csv"
                consolidated_file = out_consolidated / f"{hostname}-{server_id}.csv"

                sourceIPAddress = server["SourceIPAddress"]
                targetIPAddress = server["TargetIPAddress"] if server["TargetIPAddress"] else sourceIPAddress

                if sourceIPAddress:
                    apply_exclusions(raw_file, [], str(source_file)) # no exclusion for source
                    add_network_mappings(source_file, networks, sourceIPAddress)
                    overlay_rules(source_file, rules, str(source_file), sourceIPAddress)
 
                if targetIPAddress:
                    apply_exclusions(raw_file, exclusions, str(target_file))
                    add_network_mappings(target_file, networks, targetIPAddress)
                    overlay_rules(target_file, rules, str(target_file), targetIPAddress)
                
                    overlay_networks(target_file, networks, str(consolidated_file))
                    override_rules(consolidated_file, defaults, str(consolidated_file))
                    overlay_rules(consolidated_file, rules, str(consolidated_file), targetIPAddress)

        combine_csv_files(out_raw, out / f"1-Raw.csv")
        combine_csv_files(out_source, out / f"2-Source.csv")
        combine_csv_files(out_target, out / f"3-Target.csv")
        combine_csv_files(out_consolidated, out / f"4-Consolidated.csv")


def combine_csv_files(directory: Path, output_file: Path):
    # Get all CSV files in the directory
    csv_files = list(directory.glob('*.csv'))
    
    if not csv_files:
        print(f"No CSV files found in {directory}")
        return

    # Initialize a list to store all rows
    all_rows = []
    headers: list[str] = []

    for file in csv_files:
        with open(file, mode='r', newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            if not headers and reader.fieldnames is not None:
                headers = list(reader.fieldnames)
            for row in reader:
                all_rows.append(row)

    # Write all rows to a single output file
    with open(output_file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Combined CSV written to {output_file}")

def apply_exclusions(input_file, exclusions, output_file):
    """
    Remove rows from input_file when row['CidrIp'] matches any CIDR in `exclusions`,
    then write the remainder to output_file.

    `exclusions` can be:
      - a list/tuple/set of CIDR strings
      - a path to a CSV/text file. For CSV, it will read the 'CidrIp' column.
        For plain text, each non-empty line (before the first comma) is treated as a CIDR.
    """
    def load_cidrs(spec):
        cidrs = set()
        def add(x):
            s = (x or "").strip()
            if s:
                cidrs.add(s)

        # list-like
        if isinstance(spec, (list, tuple, set)):
            for item in spec:
                if isinstance(item, dict):
                    add(item.get("CidrIp"))
                else:
                    add(str(item))
            return cidrs

        # path-like
        p = Path(str(spec)) if spec is not None else None
        if p and p.exists():
            if p.suffix.lower() == ".csv":
                with p.open("r", newline="", encoding="utf-8-sig") as fh:
                    r = csv.DictReader(fh)
                    if r.fieldnames and "CidrIp" in r.fieldnames:
                        for row in r:
                            add(row.get("CidrIp"))
                    else:
                        # fallback: first column
                        fh.seek(0)
                        rr = csv.reader(fh)
                        next(rr, None)  # skip header-ish line
                        for row in rr:
                            if not row: 
                                continue
                            add(row[0])
            else:
                # plain text: one CIDR per line; allow "CIDR,Description"
                for line in p.read_text(encoding="utf-8").splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    add(s.split(",", 1)[0])
            return cidrs

        # single string that isn't a file path -> treat as one CIDR
        if isinstance(spec, str):
            add(spec)
        return cidrs

    excluded_cidrs = load_cidrs(exclusions)

    # Read input rules
    with open(input_file, "r", newline="", encoding="utf-8-sig") as inf:
        reader = csv.DictReader(inf)
        rows = list(reader)
        headers = reader.fieldnames or []

    # Filter
    kept = []
    dropped = 0
    for row in rows:
        cidr = (row.get("CidrIp") or "").strip()
        if cidr in excluded_cidrs:
            dropped += 1
            continue
        kept.append(row)

    # Write output
    with open(output_file, "w", newline="", encoding="utf-8") as outf:
        writer = csv.DictWriter(outf, fieldnames=headers)
        writer.writeheader()
        writer.writerows(kept)

    print(f"apply_exclusions: {dropped} excluded, {len(kept)} kept → {output_file}")

def overlay_networks(input_file, networks_file, output_file):
    input_rules = read_rules_from_csv(input_file)
    new_rules = input_rules
    if networks_file:
        networks = load_rules(networks_file)
        new_rules = [remap_cidr(r, networks) for r in new_rules]
        new_rules = deduplicate_rules(new_rules)
    new_rules = consolidate_rules(new_rules)
    write_rules_to_csv(output_file, new_rules)
    return new_rules

def add_network_mappings(input_file, networks_file, ip_address: str):
    input_rules = read_rules_from_csv(input_file)
    networks = read_rules_from_csv(networks_file)
    vm_network = get_network(ip_address, networks)

    for rule in input_rules:
        cidrIp_network = get_network(rule['CidrIp'], networks)
        if rule['Type'] == "ingress":
            rule['DstNet'] = vm_network
            rule['SrcNet'] = cidrIp_network
        else:
            rule['SrcNet'] = vm_network
            rule['DstNet'] = cidrIp_network
    write_rules_to_csv(input_file, input_rules)

def get_network(cidr_ip: str, networks: List[Dict[str, str]]) -> str:
    try:
        ip_net = ipaddress.ip_network(cidr_ip, strict=False)
        for net in networks:
            net_cidr = net.get("CidrIp", "")
            if net_cidr:
                network = ipaddress.ip_network(net_cidr, strict=False)
                if network.supernet_of(ip_net):
                    return net.get("Description", "UNKNOWN_NETWORK")
    except ValueError:
        pass
    return "UNKNOWN_NETWORK"

def overlay_rules(input_file, rules_file, output_file, ip_address: str):
    flows = read_rules_from_csv(input_file)
    rules = read_rules_from_csv(rules_file)

    for flow in flows:
        flow['Rule'] = get_network_rule(ip_address, flow, rules)

    write_rules_to_csv(output_file, flows)

def get_network_rule(ip_address, flow, rules):
    """
    Match rules where rule['Source'] and rule['Destination'] are regular
    expressions. Return the first matching rule name (or a fallback) that
    permits the flow (protocol/ports). Returns "NO_RULE_FOUND" or "ERROR".
    """
    try:
        src_str = flow.get("SrcNet", "") or ""
        dst_str = flow.get("DstNet", "") or ""

        def to_int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        f_from = to_int(flow.get("FromPort"))
        f_to = to_int(flow.get("ToPort"))
        f_proto = (flow.get("IpProtocol") or "").upper()

        for rule in rules:
            rule_name = rule.get("Name") or "UNKNOWN_RULE"
            src_pat = (rule.get("Source") or "").strip()
            dst_pat = (rule.get("Destination") or "").strip()

            # If a pattern is present, compile and test; skip rule on invalid regex
            try:
                if src_pat and not re.search(src_pat, src_str):
                    continue
                if dst_pat and not re.search(dst_pat, dst_str):
                    continue
            except re.error:
                # invalid regex -> skip this rule
                continue

            # Protocol match: rule Protocol of 'ALL' or empty means wildcard
            r_proto = (rule.get("Protocol") or "").upper()
            if r_proto and r_proto != "ALL" and r_proto != f_proto:
                continue

            r_from = to_int(rule.get("FromPort"))
            r_to = to_int(rule.get("ToPort"))

            # If rule has no port bounds, it allows any port
            if r_from is None and r_to is None:
                return rule_name

            # If flow ports are not parseable, cannot compare -> skip
            if f_from is None or f_to is None:
                continue

            # Full range comparison
            if r_from is not None and r_to is not None:
                if r_from <= f_from <= f_to <= r_to:
                    return rule_name
                else:
                    continue

            # Single-bound rules (rare) - treat as open-ended
            if r_from is not None and r_to is None:
                if r_from <= f_from:
                    return rule_name
                continue
            if r_from is None and r_to is not None:
                if f_to <= r_to:
                    return rule_name
                continue

        return "NO_RULE_FOUND"
    except Exception:
        return "ERROR"

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
    new_rules = consolidate_rules(new_rules)
    write_rules_to_csv(output_file, new_rules)
    return new_rules

def read_rules_from_csv(file_path: str) -> List[Dict[str, str]]:
    """Read security rules from a CSV file into a list of dictionaries."""
    with open(file_path, mode="r", newline="", encoding="utf-8-sig") as f:
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
    fieldnames = ["AccountId", "Hostname", "Ipv4Addresses", "Type", "IpProtocol", "FromPort", "ToPort", "CidrIp", "Description", "SrcNet", "DstNet", "Rule"]
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
