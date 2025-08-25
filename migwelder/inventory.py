import ipaddress
import csv
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


    def process(self, output_path, exclusions, networks, firewalls, defaults):
        """
        Process inventory

        For a given inventory
        1. export MGN network data (Raw)
        2. apply exclusions to remove unnecessary data.
        3. enrich data with network information and firewall check (Enriched)
        4. apply defaults and consolidate. (Processed)
        """

        out = Path(output_path)
        out_raw = out / f"1-Raw"
        out_enriched = out / f"2-Enriched"
        out_processed = out / f"3-Processed"
        out.mkdir(parents=True, exist_ok=True)
        out_raw.mkdir(parents=True, exist_ok=True)
        out_enriched.mkdir(parents=True, exist_ok=True)      
        out_processed.mkdir(parents=True, exist_ok=True)

        for server in self._inventory:
            server_id = server["MGNServerID"]
            aws_profile = server["AWSProfile"]
            self._discovery.set_profile(aws_profile)

            print(f"server: {server_id}")
            raw_file = out_raw / f"{server_id}.csv"
            if self._discovery.export_mgn_server_network_data(server_id, str(raw_file)):
                enriched_file = out_enriched / f"{server_id}.csv"
                apply_exclusions(raw_file, exclusions, str(enriched_file))
                # (enriched_file, networks, str(enriched_file))
                overlay_firewalls(enriched_file, firewalls, str(enriched_file))

                processed_file = out_processed / f"{server_id}.csv"
                overlay_networks(enriched_file, networks, str(processed_file))
                override_rules(processed_file, defaults, str(processed_file))
                overlay_firewalls(processed_file, firewalls, str(processed_file))

        combine_csv_files(out_raw, out / f"1-Raw.csv")
        combine_csv_files(out_enriched, out / f"2-Enriched.csv")
        combine_csv_files(out_processed, out / f"3-Processed.csv")


def combine_csv_files(directory: Path, output_file: Path):
    # Get all CSV files in the directory
    csv_files = list(directory.glob('*.csv'))
    
    if not csv_files:
        print(f"No CSV files found in {directory}")
        return

    # Initialize a list to store all rows
    all_rows = []
    headers = None

    for file in csv_files:
        with open(file, mode='r', newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            if headers is None:
                headers = reader.fieldnames
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


def overlay_firewalls(input_file, firewalls_file, output_file):
    input_rules = read_rules_from_csv(input_file)
    firewall_rules = read_firewall_rules(firewalls_file)
    
    for rule in input_rules:
        rule['Allowed'] = check_firewall_rules(rule, firewall_rules)
    
    write_rules_to_csv(output_file, input_rules)

def read_firewall_rules(file_path):
    firewall_rules = []
    with open(file_path, mode='r', newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                src_net = ipaddress.ip_network(row['Source'])
                dst_net = ipaddress.ip_network(row['Destination'])
                firewall_rules.append({
                    'src_net': src_net,
                    'dst_net': dst_net,
                    'type': row['Type'].upper(),
                    'from_port': int(row['FromPort']) if row['FromPort'] else None,
                    'to_port': int(row['ToPort']) if row['ToPort'] else None,
                    'ip_protocol': row['Type'].upper()
                })
            except ValueError:
                continue
    return firewall_rules

def check_firewall_rules(rule, firewall_rules):
    try:
        rule_net = ipaddress.ip_network(rule['CidrIp'])
        for fw in firewall_rules:
            if (fw['src_net'].supernet_of(rule_net) or fw['dst_net'].supernet_of(rule_net)):
                if fw['ip_protocol'] == rule['IpProtocol'].upper() or fw['ip_protocol'] == 'ALL':
                    if fw['from_port'] is None or (fw['from_port'] <= int(rule['FromPort']) <= fw['to_port']):
                        if fw['to_port'] is None or (fw['from_port'] <= int(rule['ToPort']) <= fw['to_port']):
                            return True
    except ValueError:
        return False
    return False

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
    fieldnames = ["AccountId", "Hostname", "Type", "IpProtocol", "FromPort", "ToPort", "CidrIp", "Description", "Allowed"]
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
