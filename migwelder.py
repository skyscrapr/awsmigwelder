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

    # Subcommand: process-inventory
    sd_parser = subparsers.add_parser(
        "process-inventory",
        help="Process a given inventory. Export the MGN data, enrich with known networks and apply defaults",
    )
    sd_parser.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to config folder containing defaults.csv, exclusions.csv, networks.csv, rules.csv",
    )
    sd_parser.add_argument(
        "-w",
        "--wave",
        required=True,
        help="Path to a wave file; the wave filename (stem) is used as output subfolder name.",
    )

    args = parser.parse_args()

    discovery = Discovery()
    inventory = Inventory(discovery)
    if args.command == "process-inventory":
        inventory.load_inventory(args.wave)

        # Resolve config sources (config folder takes precedence over explicit file args)
        from pathlib import Path

        config_dir = Path(args.config)
        if not config_dir.is_dir():
            raise ValueError(f"--config must be an existing directory: {config_dir}")

        networks_file = str(config_dir / "networks.csv")
        defaults_file = str(config_dir / "defaults.csv")
        exclusions_file = str(config_dir / "exclusions.csv")
        rules_file = str(config_dir / "rules.csv")

        
        from pathlib import Path

        wave_name = Path(args.wave).stem
        output_path = str(Path(args.wave).parent / wave_name)

        inventory.process(output_path, exclusions_file, networks_file, rules_file, defaults_file)


if __name__ == "__main__":
    main()
