from scapy.all import sniff, IP, wrpcap
import threading
import time
import os
import geoip2.database
from datetime import datetime

# Configurable paths and settings
EVIL_IP_FILE = "./data/blocklists/evil_ips.txt"   # One IP per line, updated by your threatfeed plugin
GEOIP_DB_PATH = "./data/geoip.mmdb"
BLOCKED_COUNTRIES = {"RU", "CN", "KP", "IR"}      # ISO country codes you want to block (customize at will)
PCAP_DIR = "./data/pcaps"

if not os.path.exists(PCAP_DIR):
    os.makedirs(PCAP_DIR)

evil_ips = set()

def load_evil_ips():
    global evil_ips
    try:
        with open(EVIL_IP_FILE, "r") as f:
            evil_ips = set(line.strip() for line in f if line.strip() and not line.startswith("#"))
        print(f"[monitor] Loaded {len(evil_ips)} evil IPs from feed.")
    except Exception as e:
        print(f"[monitor] Could not load evil IPs: {e}")

def geoip_country(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip)
            return response.country.iso_code
    except Exception:
        return None

def alert(ip, country, pkt, reason):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\033[91m[{now}] [!] ALERT: {ip} ({country}) | Reason: {reason} | {pkt.summary()}\033[0m")
    # Save PCAP for this packet (one file per event)
    pcap_name = f"{PCAP_DIR}/{ip}_{int(time.time())}.pcap"
    try:
        wrpcap(pcap_name, [pkt])
        print(f"\033[93m[monitor] Saved PCAP: {pcap_name}\033[0m")
    except Exception as e:
        print(f"[monitor] Failed to save PCAP: {e}")

def process_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Check threat feed IPs (both src and dst)
        if src in evil_ips:
            country = geoip_country(src)
            alert(src, country, pkt, "SOURCE is EVIL IP")
        elif dst in evil_ips:
            country = geoip_country(dst)
            alert(dst, country, pkt, "DEST is EVIL IP")
        else:
            # Check GeoIP country blocks
            src_country = geoip_country(src)
            dst_country = geoip_country(dst)
            if src_country in BLOCKED_COUNTRIES:
                alert(src, src_country, pkt, "SOURCE country blocked")
            elif dst_country in BLOCKED_COUNTRIES:
                alert(dst, dst_country, pkt, "DEST country blocked")

def evil_ip_reloader():
    # Background thread to reload threat feeds every 5 minutes
    while True:
        load_evil_ips()
        time.sleep(300)  # 5 min

def run():
    print("[monitor] Sniffing all traffic, detecting evil IPs, blocking countries, saving PCAPs...")
    load_evil_ips()
    threading.Thread(target=evil_ip_reloader, daemon=True).start()
    sniff(filter="ip", prn=process_packet, store=0)