import os
import re
import requests
from collections import defaultdict
from urllib.parse import urlparse

DOMAIN_PATTERN = re.compile(r"\s+")

def extract_domain(line):
    line = line.strip()
    if line.startswith("#") or not line:
        return None
    parts = DOMAIN_PATTERN.split(line)
    if len(parts) == 1 and "." in parts[0]:
        return parts[0]
    elif len(parts) >= 2:
        return parts[1]
    return None

def readable_size(path):
    size = os.path.getsize(path)
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size/1024:.1f} KB"
    else:
        return f"{size/1024**2:.2f} MB"

def get_filename_from_url(url):
    """Extract a meaningful filename from URL path"""
    parsed = urlparse(url)
    path = parsed.path

    filename = os.path.basename(path)

    if not filename:
        filename = parsed.netloc

    if not filename.endswith(('.txt', '.hosts')):
        filename += '.txt'
    return filename

def fetch_from_url(url):
    """Fetch content from a URL"""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()  
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return []

def combine_hosts_from_urls():

    urls = [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
        "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo_noadult.txt",
        "https://adaway.org/hosts.txt",
        "https://github.com/ignaciocastro/a-dove-is-dumb/raw/main/pihole.txt",
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/cryptominers.txt",
        "https://github.com/AdguardTeam/FiltersRegistry/raw/master/filters/filter_4_Social/filter.txt",
        "https://filters.adtidy.org/extension/ublock/filters/3.txt",
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
        "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/mobile.txt",
        "https://energized.pro/mirror/duckduckgo-tracker-blocklists.txt",
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
        "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_specific.txt",
        "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty.txt",
        "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_thirdparty_international.txt",
        "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_admiral.txt",
        "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_general.txt",
        "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_trackingservers_thirdparty.txt",
        "https://hosts.tweedge.net/malicious.txt",
        "https://energized.pro/mirror/exodus-privacy-trackers.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.tiktok.extended.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/native.xiaomi.txt",
        "https://gitlab.com/quidsup/notrack-annoyance-blocklist/raw/master/notrack-annoyance.txt",
        "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
        "https://big.oisd.nl/",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&mimetype=plaintext&useip=0.0.0.0",
        "https://someonewhocares.org/hosts/zero/",
        "https://ublockorigin.pages.dev/filters/filters.min.txt",
        "https://ublockorigin.github.io/uAssetsCDN/filters/privacy.min.txt",
        "https://filters.adavoid.org/ultimate-privacy-filter.txt",
        "https://www.usom.gov.tr/url-list.txt",
        "https://energized.pro/mirror/whotracks-me.txt",
        "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        "https://zonefiles.io/f/compromised/domains/live/",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
        "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
        "https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
        "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt",
        "https://raw.githubusercontent.com/jamiemansfield/minecraft-hosts/master/lists/tracking.txt",
        "https://urlhaus.abuse.ch/downloads/hostfile/"

    ]

    all_domains = set()
    source_domains = defaultdict(set)

    whitelist_keywords = {

        "facebook.com",
        "fbcdn.net",
        "fb.com",
        "video.xx.fbcdn.net",
        "scontent.xx.fbcdn.net",
        "upload.facebook.com",
        "graph.facebook.com",
        "graph-video.facebook.com",
        "edge-chat.facebook.com",
        "media.xx.fbcdn.net",

        "instagram.com",
        "cdninstagram.com",
        "scontent.cdninstagram.com",
        "graph.instagram.com",
        "graph.facebook.net",
        "igcdn.com",
        "ig.me",

        "whatsapp.com",
        "web.whatsapp.com",
        "api.whatsapp.com",
        "mmg.whatsapp.net",
        "media.whatsapp.net",
        "static.whatsapp.net",
        "wa.me",

        "business.whatsapp.com",

        "telegram.org",
        "t.me",
        "cdn.telegram.org"
    }

    whitelist_set = set(whitelist_keywords)

    tracker_keywords = {"analytics", "pixel", "tag", "track", "log", "insight"}

    for url in urls:
        source_name = get_filename_from_url(url)
        print(f"Fetching from {url}...")

        lines = fetch_from_url(url)

        for line in lines:
            domain = extract_domain(line)
            if domain:
                domain = domain.lower()
                all_domains.add(domain)
                source_domains[source_name].add(domain)

        print(f"- Found {len(source_domains[source_name])} domains in {source_name}")

    safesearch_block = [
        "# Disable SafeSearch",
        "216.239.38.120 forcesafesearch.google.com",
        "216.239.38.120 restrict.youtube.com",
        "216.239.38.120 safe.duckduckgo.com",
        "216.239.38.120 bing.com",
        "",
    ]

    outputs = {
        "windows_hosts": lambda d: f"0.0.0.0 {d}",
        "android_hosts": lambda d: f"127.0.0.1 {d}",
        "dnsmasq.conf": lambda d: f"address=/{d}/0.0.0.0",
        "ublock.txt": lambda d: f"||{d}^",
        "combined.txt": lambda d: d,
    }

    def is_tracker(domain):
        return any(keyword in domain for keyword in tracker_keywords)

    def is_whitelisted(domain):
        return any(domain.endswith(wl) or domain == wl for wl in whitelist_set)

    for filename, formatter in outputs.items():
        with open(filename, "w", encoding="utf-8") as f:
            for source_file, domains in source_domains.items():

                tracker_domains = []
                other_domains = []
                white_domains = []

                for domain in domains:
                    if is_whitelisted(domain):
                        white_domains.append(domain)
                    elif is_tracker(domain):
                        tracker_domains.append(domain)
                    else:
                        other_domains.append(domain)

                tracker_domains.sort()
                other_domains.sort()
                white_domains.sort()

                f.write(f"# === Source: {source_file} ===\n")

                if tracker_domains:
                    f.write("# === Tracker / Analytics ===\n")
                    for d in tracker_domains:
                        f.write(formatter(d) + "\n")

                if other_domains:
                    f.write("\n# === General Blocked Domains ===\n")
                    for d in other_domains:
                        f.write(formatter(d) + "\n")

                if white_domains:
                    f.write("\n# === Whitelisted Domains (not blocked) ===\n")
                    for d in white_domains:
                        f.write(f"# {formatter(d)} (whitelisted)\n")

                f.write("\n")

            if filename in ["windows_hosts", "android_hosts"]:
                f.write("\n".join(safesearch_block))

    print(f"\n✅ {len(all_domains)} total unique domains processed.\n")
    print("📦 File sizes:")
    for filename in outputs.keys():
        print(f"- {filename}: {readable_size(filename)}")

if __name__ == "__main__":
    combine_hosts_from_urls()
