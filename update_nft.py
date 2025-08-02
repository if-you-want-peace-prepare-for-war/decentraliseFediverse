#!/usr/bin/env python3

import asyncio
import ipaddress
import aiohttp
import re
import sys
import json
import nftables

async def extract_json_url_from_html(session, url):
    html = await fetch_text(session, url)
    if not html:
        print(f"Could not fetch or parse the download page at {url}")
        return None
    # Regex to find ServiceTags_Public_*.json (direct download)
    match = re.search(r'https:\/\/download\.microsoft\.com\/download\/[^\"]*ServiceTags_Public_\d+\.json', html)
    if match:
        return match.group(0)
    print("No ServiceTags_Public JSON link found on the page.")
    return None

async def fetch_json(session, url):
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
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.text()
    except aiohttp.ClientError as e:
        print(f"Error fetching {url}: {e}")
        return None

async def get_amazon_cidrs(session):
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
    url_v4 = "https://www.cloudflare.com/ips-v4"
    url_v6 = "https://www.cloudflare.com/ips-v6"
    text_v4 = await fetch_text(session, url_v4)
    text_v6 = await fetch_text(session, url_v6)
    cidrs_v4 = text_v4.split() if text_v4 else []
    cidrs_v6 = text_v6.split() if text_v6 else []
    print(f"Fetched {len(cidrs_v4)} Cloudflare IPv4, {len(cidrs_v6)} IPv6 CIDRs")
    return cidrs_v4, cidrs_v6

async def get_google_cidrs(session):
    url = "https://www.gstatic.com/ipranges/cloud.json"
    data = await fetch_json(session, url)
    if data:
        cidrs_v4 = [prefix['ipv4Prefix'] for prefix in data['prefixes'] if 'ipv4Prefix' in prefix]
        cidrs_v6 = [prefix['ipv6Prefix'] for prefix in data['prefixes'] if 'ipv6Prefix' in prefix]
        print(f"Fetched {len(cidrs_v4)} Google IPv4, {len(cidrs_v6)} IPv6 CIDRs")
        return cidrs_v4, cidrs_v6
    return [], []

async def get_microsoft_cidrs(session):
    # Always fetch the latest JSON link from the Microsoft download page
    page_url = "https://www.microsoft.com/en-my/download/details.aspx?id=56519"
    json_url = await extract_json_url_from_html(session, page_url)
    if not json_url:
        print("Could not find the Microsoft Service Tags JSON URL.")
        return [], []
    data = await fetch_json(session, json_url)
    if data:
        cidrs_v4 = [
            prefix
            for value in data['values']
            for prefix in value['properties']['addressPrefixes']
            if ipaddress.ip_network(prefix, strict=False).version == 4
        ]
        cidrs_v6 = [
            prefix
            for value in data['values']
            for prefix in value['properties']['addressPrefixes']
            if ipaddress.ip_network(prefix, strict=False).version == 6
        ]
        print(f"Fetched {len(cidrs_v4)} Microsoft IPv4, {len(cidrs_v6)} IPv6 CIDRs")
        return cidrs_v4, cidrs_v6
    return [], []

def remove_overlapping_networks(cidrs):
    """Remove overlapping CIDRs, keeping only the broadest ranges."""
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]
    networks.sort(key=lambda x: x.prefixlen, reverse=True)
    filtered_networks = []
    for network in networks:
        if not any(network.overlaps(existing) for existing in filtered_networks):
            filtered_networks.append(network)
    filtered_cidrs = [str(net) for net in filtered_networks]
    print(f"Reduced CIDR count from {len(cidrs)} to {len(filtered_cidrs)}")
    return filtered_cidrs

def ensure_table(nft, table="inet", name="filter"):
    nft.cmd(f"add table {table} {name} 2>/dev/null || true")

def ensure_set(nft, table, set_name, addr_type):
    nft.cmd(f"add set {table} filter {set_name} {{ type {addr_type}; flags interval; auto-merge; }} 2>/dev/null || true")

def flush_set(nft, table, set_name):
    nft.cmd(f"flush set {table} filter {set_name} 2>/dev/null || true")

def add_elements(nft, table, set_name, cidrs):
    # Add in batches for large lists
    BATCH = 200
    for i in range(0, len(cidrs), BATCH):
        batch = ', '.join(cidrs[i:i+BATCH])
        nft.cmd(f"add element {table} filter {set_name} {{ {batch} }}")

def update_nftables_sets(v4cidrs, v6cidrs):
    nft = nftables.Nftables()
    nft.set_output(json=True)
    # Ensure table and sets exist
    ensure_table(nft, "inet", "filter")
    ensure_set(nft, "inet", "crimeFlare4", "ipv4_addr")
    ensure_set(nft, "inet", "crimeFlare6", "ipv6_addr")
    # Flush sets
    flush_set(nft, "inet", "crimeFlare4")
    flush_set(nft, "inet", "crimeFlare6")
    # Add all elements
    if v4cidrs:
        add_elements(nft, "inet", "crimeFlare4", v4cidrs)
        print(f"Added {len(v4cidrs)} IPv4 CIDRs to crimeFlare4")
    if v6cidrs:
        add_elements(nft, "inet", "crimeFlare6", v6cidrs)
        print(f"Added {len(v6cidrs)} IPv6 CIDRs to crimeFlare6")

async def gather_all_cidrs():
    async with aiohttp.ClientSession() as session:
        google_v4, google_v6 = await get_google_cidrs(session)
        cloudflare_v4, cloudflare_v6 = await get_cloudflare_cidrs(session)
        amazon_v4 = await get_amazon_cidrs(session)
        microsoft_v4, microsoft_v6 = await get_microsoft_cidrs(session)

    all_v4 = google_v4 + cloudflare_v4 + amazon_v4 + microsoft_v4
    all_v6 = google_v6 + cloudflare_v6 + microsoft_v6
    filtered_v4 = remove_overlapping_networks(all_v4)
    filtered_v6 = remove_overlapping_networks(all_v6)
    return filtered_v4, filtered_v6

def write_cidrs_to_json(v4cidrs, v6cidrs, filename="cidrs.json"):
    data = {
        "ipv4": v4cidrs,
        "ipv6": v6cidrs
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote {len(v4cidrs)} IPv4 and {len(v6cidrs)} IPv6 CIDRs to {filename}")

async def main():
    print("Fetching CIDR lists...")
    v4cidrs, v6cidrs = await gather_all_cidrs()
    print("Updating nftables sets (requires root)...")
    update_nftables_sets(v4cidrs, v6cidrs)
    print("nftables sets crimeFlare4 and crimeFlare6 updated.")

async def main():
    print("Fetching CIDR lists...")
    v4cidrs, v6cidrs = await gather_all_cidrs()
    write_cidrs_to_json(v4cidrs, v6cidrs)  # <-- Add this line
    print("Updating nftables sets (requires root)...")
    update_nftables_sets(v4cidrs, v6cidrs)
    print("nftables sets crimeFlare4 and crimeFlare6 updated.")
