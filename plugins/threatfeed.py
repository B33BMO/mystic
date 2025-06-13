import time
import requests
import os
import ipaddress

def colorize(text, color):
    colors = {
        "cyan": "\033[36m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "red": "\033[31m",
        "magenta": "\033[35m",
        "bright_green": "\033[92m",
        "reset": "\033[0m"
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"

THREAT_FEEDS = [
    {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "category": "general"
    },
    {
        "url": "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
        "category": "compromised"
    },
    {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "category": "ci_army"
    },
    {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "category": "spamhaus"
    },
    {"url": "https://reputation.alienvault.com/reputation.generic", "category": "alienvault"},
    {"url": "https://lists.blocklist.de/lists/all.txt", "category": "blocklistde"},
    {"url": "https://check.torproject.org/torbulkexitlist", "category": "tor_exit"},
    {"url": "http://malc0de.com/bl/IP_Blacklist.txt", "category": "malc0de"},
    {"url": "https://www.dshield.org/ipsascii.html?limit=10000", "category": "dshield"},
]

EVIL_IP_FILE = "./data/blocklists/evil_ips.txt"
EVIL_IPS_TAGGED_FILE = "./data/blocklists/evil_ips_tagged.txt"

# AbuseIPDB stub (set your API key here if you have one)
ABUSEIPDB_API_KEY = "2ae20b7ff48b3d2c65ff625894b646554945305632afaf16820bddab526a3b0004e1d50255b522aa"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"
ABUSEIPDB_CATEGORY = "abuseipdb"

def parse_ips_and_cidrs(text):
    ip_category_map = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Remove inline comments
        line = line.split()[0]
        try:
            # Check for CIDR (expand)
            if "/" in line:
                net = ipaddress.ip_network(line, strict=False)
                for ip in net.hosts():
                    ip_category_map[str(ip)] = None  # We'll assign category in the main loop
            else:
                # Single IP
                ipaddress.ip_address(line)  # throws if not valid
                ip_category_map[line] = None
        except Exception:
            continue
    return ip_category_map

def fetch_and_update():
    all_ips = set()
    ip_to_cat = {}
    for feed in THREAT_FEEDS:
        url = feed["url"]
        category = feed["category"]
        try:
            print(colorize(f"\n[threatfeed] Fetching {url}", "cyan"))
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            feed_ips = parse_ips_and_cidrs(resp.text)
            # Tag each IP with the feed's category
            for ip in feed_ips:
                all_ips.add(ip)
                ip_to_cat[ip] = category
            print(colorize(f"[threatfeed] Category: {category}", "cyan"))
            print(colorize(f"[threatfeed] {len(feed_ips)} IPs parsed for {category}", "green"))
            # Show a sample of up to 3 IPs
            sample_ips = list(feed_ips.keys())[:3]
            if sample_ips:
                print(colorize(f"[threatfeed] Sample IPs: {', '.join(sample_ips)}", "magenta"))
            else:
                print(colorize("[threatfeed] No IPs found in this feed.", "yellow"))
        except Exception as e:
            print(colorize(f"[threatfeed] Failed to fetch {url}: {e}", "yellow"))
    # AbuseIPDB integration (optional/premium)
    if ABUSEIPDB_API_KEY:
        print(colorize("[threatfeed] Fetching from AbuseIPDB (premium feature!)", "magenta"))
        try:
            headers = {
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            params = {
                "confidenceMinimum": "90"
            }
            resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if "data" in data:
                abuseipdb_count = 0
                abuseipdb_samples = []
                for entry in data["data"]:
                    ip = entry["ipAddress"]
                    all_ips.add(ip)
                    ip_to_cat[ip] = ABUSEIPDB_CATEGORY
                    abuseipdb_count += 1
                    if len(abuseipdb_samples) < 3:
                        abuseipdb_samples.append(ip)
                print(colorize(f"[threatfeed] {abuseipdb_count} IPs from AbuseIPDB", "green"))
                if abuseipdb_samples:
                    print(colorize(f"[threatfeed] Sample AbuseIPDB IPs: {', '.join(abuseipdb_samples)}", "magenta"))
            else:
                print(colorize("[threatfeed] No IPs found from AbuseIPDB.", "yellow"))
        except Exception as e:
            print(colorize(f"[threatfeed] AbuseIPDB fetch failed: {e}", "yellow"))

    # Write all unique IPs to evil_ips.txt (flat, one per line)
    os.makedirs(os.path.dirname(EVIL_IP_FILE), exist_ok=True)
    with open(EVIL_IP_FILE, "w") as f:
        for ip in sorted(all_ips):
            f.write(f"{ip}\n")
    print(colorize(f"\n[threatfeed] Updated evil IP list: {len(all_ips)} total unique IPs", "bright_green"))
    # Show a sample of up to 10 IPs from all feeds
    sample_all = list(all_ips)[:10]
    if sample_all:
        print(colorize(f"[threatfeed] Sample total evil IPs: {', '.join(sample_all)}", "magenta"))
    else:
        print(colorize("[threatfeed] No evil IPs written at all!", "red"))

    # Also write tagged version (IP\tcategory)
    with open(EVIL_IPS_TAGGED_FILE, "w") as f:
        for ip in sorted(all_ips):
            cat = ip_to_cat.get(ip, "unknown")
            f.write(f"{ip}\t{cat}\n")

def run():
    while True:
        fetch_and_update()
        time.sleep(1800)  # 30 min