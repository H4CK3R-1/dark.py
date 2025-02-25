import argparse
import os
import socket
import subprocess
import sys
from argparse import ArgumentParser
from ipaddress import ip_network

import ipinfo
import requests
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# Banner
banner = f"""
{Fore.CYAN}
    =====================================
    |        DARK TOOL v1.0            |
    |      Created by Pratham          |
    =====================================
{Fore.RESET}
"""
print(banner)

# Argument Parser Setup
parser: ArgumentParser = argparse.ArgumentParser(description='Dark Tool V1 - Bug Bounty Recon & Scanning Tool')

# Argument parser setup
parser = argparse.ArgumentParser(description="WhatWeb Scanner Integration")
parser.add_argument('-wb', '--whatweb', type=str, help='Scan a website using WhatWeb')

# Arguments ko parse karna
args = parser.parse_args()

# WhatWeb Command Execution
if args.whatweb:
    try:
        print(f"[+] Scanning {args.whatweb} using WhatWeb...\n")
        result = subprocess.run(['whatweb', args.whatweb], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[-] Error: {e}")

# Argument Groups
fuzzing_group = parser.add_argument_group('Fuzzing')
vuln_group = parser.add_argument_group('Vulnerability Scans')
nuclei_group = parser.add_argument_group('Nuclei Scans')
passiverecon_group = parser.add_argument_group('Passive Recon')
update_group = parser.add_argument_group('Update Options')
ip_group = parser.add_argument_group('IP Information')
cloud_group = parser.add_argument_group('Cloud Security')

# Fuzzing Arguments
fuzzing_group.add_argument('-ar', '--autorecon', type=str, help='Auto recon for target domain', metavar='domain.com')
fuzzing_group.add_argument('-f_p', '--forbidden_pages', type=str, help='Find forbidden pages', metavar='domain.com')
fuzzing_group.add_argument('-e', '--extensions', help='Comma-separated list of file extensions to scan', default='')
fuzzing_group.add_argument('-x', '--exclude', help='Comma-separated list of status codes to exclude', default='')

# Vulnerability Arguments
vuln_group.add_argument('-jwt', '--jwt_scan', type=str, help='Analyze JWT token for vulnerabilities', metavar='token')
vuln_group.add_argument('-jwt-modify', '--jwt_modify', type=str, help='Modify JWT token', metavar='token')
vuln_group.add_argument('-heapds', '--heapdump_file', type=str, help='File for heapdump scan', metavar='heapdump.txt')
vuln_group.add_argument('-heapts', '--heapdump_target', type=str, help='Target for heapdump scan', metavar='domain.com')
vuln_group.add_argument('-zt', '--zone-transfer', type=str, help='Test for DNS zone transfer vulnerability', metavar='domain.com')

# Nuclei & Passive Recon
nuclei_group.add_argument('-nl', '--nuclei_lfi', action='store_true', help='Find Local File Inclusion with Nuclei')
passiverecon_group.add_argument('-gs', '--google', action='store_true', help='Perform Google search for recon')

# Update Arguments
update_group.add_argument('-u', '--update', action='store_true', help='Update the script')

# General Arguments
parser.add_argument('--s3-scan', help='Scan for exposed S3 buckets')
parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
parser.add_argument('-c', '--concurrency', type=int, default=10, help='Maximum concurrent requests')
parser.add_argument('--shodan-api', help='Shodan API key for enumeration')
parser.add_argument('--proxy', help='Use proxy (e.g., http://proxy.com:8080)')
parser.add_argument('--proxy-file', help='Load proxies from file')
parser.add_argument('--heapdump', help='Analyze Java heapdump file')
parser.add_argument('--output-dir', help='Output directory', default='.')

# Cloud Security Arguments
cloud_group.add_argument('-aws', '--aws-scan', type=str, help='Scan exposed AWS resources', metavar='domain.com')
cloud_group.add_argument('-az', '--azure-scan', type=str, help='Scan exposed Azure resources', metavar='domain.com')

# IP Information
ip_group.add_argument('--ipinfo', type=str, help='Get IP info for domain/IP', metavar='TARGET')
ip_group.add_argument('--token', type=str, help='IPinfo API token', metavar='TOKEN')
ip_group.add_argument('--save-ranges', type=str, help='Save IP ranges to file', metavar='FILENAME')

args = parser.parse_args()

def scan_ip_info(target, token):
    try:
        ip = socket.gethostbyname(target)
        print(f"{Fore.CYAN}Resolved {target} to {ip}{Style.RESET_ALL}")
        handler = ipinfo.getHandler(token)
        details = handler.getDetails(ip)

        print(f"{Fore.GREEN}IP Info:{Style.RESET_ALL}")
        print(f"IP: {details.ip}")
        if hasattr(details, 'hostname'):print(f"Hostname: {details.hostname}")
        if hasattr(details, 'org'): print(f"Organization: {details.org}")
        if hasattr(details, 'country'): print(f"Country: {details.country}")

        if hasattr(details, 'org'):
            org_parts = details.org.split()
            asn = org_parts[0]
            org_name = ' '.join(org_parts[1:])
            print(f"ASN: {asn}, Org: {org_name}")
            response = requests.get(f"https://ipinfo.io/{asn}/prefixes?token={token}")
            if response.status_code == 200:
                prefixes = response.json().get('prefixes', [])
                for prefix in prefixes:
                    network = ip_network(prefix.get('netblock', ''))
                    print(f"Range: {network} ({network.num_addresses} IPs)")

    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

if args.ipinfo:
    if not args.token:
        print(f"{Fore.RED}Error: IPinfo API token required. Use --token to provide it.{Style.RESET_ALL}")
        sys.exit(1)
    scan_ip_info(args.ipinfo, args.token)

def update_script():
    backup_dir = "backups"
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    print(f"{Fore.CYAN}Backup directory created at {backup_dir}{Style.RESET_ALL}")

if args.update:
    update_script()
    print(f"{Fore.GREEN}Script updated successfully!{Style.RESET_ALL}")
