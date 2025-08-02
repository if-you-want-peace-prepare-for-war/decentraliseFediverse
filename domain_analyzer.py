#!/usr/bin/env python3.12

"""
This script analyzes a list of domains to determine if they are hosted on major
tech platforms (Amazon, Cloudflare, Google, Microsoft). It fetches IP/CIDR ranges
for these platforms, resolves the domains to IP addresses, and checks if the
resolved IPs fall within the fetched ranges. The script uses asynchronous
programming for efficient operation and provides detailed output to the CLI.

Copyright © spirillen, AGPLv3.
"""

import asyncio
import ipaddress
import json
import argparse
import re
import sys
import socket
import os
import aiohttp
import aiohttp_socks
from colorama import Fore, Style, init


__version__ = "1.3.3"

# Initialize colorama for cross-platform color support
init()

async def fetch_json(session, url):
    """Fetch JSON data from a URL."""
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.json(content_type=None)
    except aiohttp.ClientError as e:
        print(f"Error fetching {url}: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {url}: {e}")
        return None


async def fetch_text(session, url):
    """Fetch text data from a URL."""
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.text()
    except aiohttp.ClientError as e:
        print(f"Error fetching {url}: {e}")
        return None

async def get_amazon_cidrs(session):
    """Fetch Amazon CIDRs."""
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    data = await fetch_json(session, url)
    if data:
        cidrs = [
            prefix['ip_prefix']
            for prefix in data['prefixes']
            if (prefix['service'].upper() == "CLOUDFRONT" or
                prefix['service'].upper() == "EC2" or
                prefix['service'].upper() == "S3")
        ]
        print(f"Fetched {len(cidrs)} Amazon CIDRs")
        return cidrs
    return []

async def get_cloudflare_cidrs(session):
    """Fetch Cloudflare CIDRs."""
    url = "https://www.cloudflare.com/ips-v4"
    text = await fetch_text(session, url)
    if text:
        cidrs = text.split()
        print(f"Fetched {len(cidrs)} Cloudflare CIDRs")
        return cidrs
    return []

async def get_google_cidrs(session):
    """Fetch Google CIDRs."""
    url = "https://www.gstatic.com/ipranges/cloud.json"
    data = await fetch_json(session, url)
    if data:
        cidrs = [prefix['ipv4Prefix'] for prefix in data['prefixes'] if 'ipv4Prefix' in prefix]
        print(f"Fetched {len(cidrs)} Google CIDRs")
        return cidrs
    return []

async def get_latest_msft_servicetags_url(session):
    """Scrape the Microsoft download page for the latest ServiceTags_Public JSON direct link."""
    page_url = "https://www.microsoft.com/en-my/download/details.aspx?id=56519"
    html = await fetch_text(session, page_url)
    if not html:
        print("Could not fetch Microsoft download page.")
        return None
    # Regex for ServiceTags_Public_YYYYMMDD.json URL
    match = re.search(r"https:\/\/download\.microsoft\.com\/download\/[^\"]*ServiceTags_Public_\d+\.json", html)
    if match:
        return match.group(0)
    print("Could not find ServiceTags_Public JSON link in Microsoft download page.")
    return None

async def get_microsoft_cidrs(session):
    """Fetch Microsoft CIDRs dynamically from the latest ServiceTags_Public JSON."""
    json_url = await get_latest_msft_servicetags_url(session)
    if not json_url:
        return []
    data = await fetch_json(session, json_url)
    if data:
        cidrs = [
            prefix
            for value in data['values']
            for prefix in value['properties']['addressPrefixes']
            if ipaddress.ip_network(prefix).version == 4  # Filter IPv4 only
        ]
        print(f"Fetched {len(cidrs)} Microsoft CIDRs")
        return cidrs
    return []

def remove_overlapping_networks(cidrs):
    """Remove overlapping CIDRs, keeping only the broadest ranges."""
    # This implementation is less efficient but more robust against KeyboardInterrupts
    networks = [ipaddress.ip_network(cidr) for cidr in cidrs]
    networks.sort(key=lambda x: x.prefixlen, reverse=True)  # Start with the largest networks

    filtered_networks = []
    total_networks = len(networks)
    for i, network in enumerate(networks):
        try:
            # Check if the current network contains any of the already filtered networks
            if not any(network.overlaps(filtered_net) for filtered_net in filtered_networks):
                filtered_networks.append(network)
            # Print progress on the same line
            print(f"\rProcessed {i+1}/{total_networks} networks", end="")
            sys.stdout.flush()  # Ensure the output is flushed immediately

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Returning partially filtered CIDRs.")
            break
    # Clear the progress line
    print(" " * 80, end='\r')
    sys.stdout.flush()

    filtered_cidrs = [str(net) for net in filtered_networks]
    print(f"Reduced CIDR count from {len(cidrs)} to {len(filtered_cidrs)} after removing overlaps")
    return filtered_cidrs

async def analyze_domains(input_file, output_file, cidrs, dns_resolver=None):
    """Analyze domains from a file and identify those hosted on the given CIDR ranges."""

    active_domains = []
    inactive_domains = []

    try:
        with open(input_file, 'r', encoding="utf-8") as f:
            domains = [line.strip() for line in f]
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return

    async with aiohttp.ClientSession() as session:
        for domain in domains:
            try:
                # Resolve domain to IP address
                # Use specified DNS resolver if provided
                if dns_resolver:
                    resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    resolver.connect((dns_resolver, 53))  # DNS port is 53

                    def resolve_with_custom_dns(domain):
                        try:
                            return socket.getaddrinfo(domain, None, socket.AF_INET)
                        except socket.gaierror as e:
                            print(f"DNS resolution error for {domain}: {e}")
                            return None

                    ip_info = await asyncio.get_event_loop().run_in_executor(None, resolve_with_custom_dns, domain)
                    if ip_info:
                        ip_address = ip_info[0][4][0]  # Extract IP from the result
                    else:
                        inactive_domains.append(domain)
                        print(f"Domain {domain} could not be resolved using custom DNS resolver.")
                        continue
                else:
                    resolver = asyncio.get_event_loop().getaddrinfo
                    ip_info = await resolver(domain, None)
                    ip_address = ip_info[0][4][0]  # Extract IP from the result

                ip_obj = ipaddress.ip_address(ip_address)

                # Check if the IP is within any of the CIDR ranges
                is_unsafe = any(ip_obj in ipaddress.ip_network(cidr) for cidr in cidrs)

                if is_unsafe:
                    color = Fore.YELLOW  # Neon orange (ish) for unsafe
                    active_domains.append(domain)
                    print(f"{Fore.WHITE}Domain {color}{domain}{Fore.WHITE} resolves to {ip_address} and is {color}within{Fore.WHITE} the target CIDR ranges.")
                else:
                    color = Fore.CYAN  # Neon blue for safe
                    active_domains.append(domain)
                    print(f"{Fore.WHITE}Domain {color}{domain}{Fore.WHITE} resolves to {ip_address} but is {color}NOT{Fore.WHITE} within the target CIDR ranges.")

            except Exception as e:
                inactive_domains.append(domain)
                print(f"{Fore.RED}Domain {domain} could not be resolved: {e}{Style.RESET_ALL}")

    # Write the filtered domains to the output file
    with open(output_file, 'w', encoding="utf-8") as f:
        for domain in active_domains:
            f.write(f"{domain}\n")

    print(f"{Fore.GREEN}Found {len(active_domains)} active domains.{Style.RESET_ALL} Results saved to {output_file}")
    print(f"{Fore.RED}Found {len(inactive_domains)} inactive domains.{Style.RESET_ALL}")

async def main():
    """Main function to orchestrate the CIDR fetching and domain analysis."""
    parser = argparse.ArgumentParser(description="Analyze domains to identify those hosted on major tech platforms.",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-i", "--input", dest="input_file", default="instance.txt",
                        help="Input file containing domains (default: instance.txt)")
    parser.add_argument("-o", "--output", dest="output_file", default="filtered_domains.txt",
                        help="Output file to write filtered domains (default: filtered_domains.txt)")
    parser.add_argument("-s", "--socks5", dest="socks_proxy",
                        help="SOCKS5 proxy address (e.g., socks5://127.0.0.1:9050)")
    parser.add_argument("-d", "--dns", dest="dns_resolver", default="192.168.56.3",
                        help="DNS resolver to use (e.g., 192.168.56.3)")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--description", action="help", help="""This script analyzes
a list of domains to determine if they are hosted on major tech platforms (Amazon,
Cloudflare, Google, Microsoft). It fetches IP/CIDR ranges for these platforms,
resolves the domains to IP addresses, and checks if the resolved IPs fall within
the fetched ranges. The script uses asynchronous programming for efficient
operation and provides detailed output to the CLI. Copyright © spirillen, AGPLv3.""")

    args = parser.parse_args()

    print("Starting domain analysis script...")
    print(f"Using input file: {args.input_file}")
    print(f"Using output file: {args.output_file}")
    if args.socks_proxy:
        print(f"Using SOCKS5 proxy: {args.socks_proxy}")
    else:
        print("Not using a SOCKS5 proxy.")

    print(f"Using DNS resolver: {args.dns_resolver}")

    # Create a SOCKS proxy connector if a SOCKS proxy is provided
    if args.socks_proxy:
        try:
            connector = aiohttp_socks.ProxyConnector.from_url(args.socks_proxy)
        except ValueError as e:
            print(f"Invalid SOCKS proxy URL: {e}")
            return  # Exit if the proxy URL is invalid
        session = aiohttp.ClientSession(connector=connector)
    else:
        session = aiohttp.ClientSession()

    try:
        # Fetch CIDRs
        google_cidrs = await get_google_cidrs(session)
        cloudflare_cidrs = await get_cloudflare_cidrs(session)
        amazon_cidrs = await get_amazon_cidrs(session)
        microsoft_cidrs = await get_microsoft_cidrs(session)

        # Combine and filter CIDRs
        all_cidrs = google_cidrs + cloudflare_cidrs + amazon_cidrs + microsoft_cidrs
        filtered_cidrs = remove_overlapping_networks(all_cidrs)
        print(f"\nTotal filtered CIDR count: {len(filtered_cidrs)}")

        # Analyze domains
        await analyze_domains(args.input_file, args.output_file, filtered_cidrs, args.dns_resolver)
    finally:
        await session.close()

if __name__ == "__main__":
    asyncio.run(main())
