""" discovery """
import logging
import boto3
import csv
import requests
import botocore.auth
import botocore.awsrequest
import botocore.session
import json


LOGGER = logging.getLogger(__name__)


class EC2:
    """ EC2 """

    def export_security_group_rules(self, security_group_id: str, output_path: str):
        """
        Exports security group rules for a given security_group_id to a CSV file.

        Args:
            output_file (str): Path to output CSV file.
        """
        logging.info(f"Looking up Security Groups by ID: {security_group_id}")
        client = boto3.client('ec2')
        security_groups = client.describe_security_groups(
            GroupIds=[security_group_id]
        )

        rules = []
        for sg in security_groups['SecurityGroups']:
            for rule in sg.get('IpPermissionsEgress', []):
                for ip_range in rule.get('IpRanges', []):
                    rules.append({
                        'Type': "egress",
                        'IpProtocol': rule.get('IpProtocol', ''),
                        'FromPort': rule.get('FromPort', ''),
                        'ToPort': rule.get('ToPort', ''),
                        'CidrIp': ip_range.get('CidrIp', ''),
                        'Description': ip_range.get('Description', '')
                    })
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    rules.append({
                        'Type': "ingress",
                        'IpProtocol': rule.get('IpProtocol', ''),
                        'FromPort': rule.get('FromPort', ''),
                        'ToPort': rule.get('ToPort', ''),
                        'CidrIp': ip_range.get('CidrIp', ''),
                        'Description': ip_range.get('Description', '')
                    })

        logging.info(f"Writing {len(rules)} rules to {output_path}")
        with open(output_path, mode='w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['Type', 'IpProtocol', 'FromPort', 'ToPort', 'CidrIp', 'Description'])
            writer.writeheader()
            for rule in rules:
                writer.writerow(rule)
