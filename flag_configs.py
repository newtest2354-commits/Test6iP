import os
import re
import json
import base64
import socket
import ipaddress
import requests
from datetime import datetime
from urllib.parse import urlparse, unquote, quote
from collections import defaultdict
import time

class ConfigFlagger:
    def __init__(self):
        self.categories = [
            'vmess', 'vless', 'trojan', 'ss',
            'hysteria2', 'hysteria', 'tuic',
            'wireguard', 'other'
        ]
        self.tiers = [50, 100, 150, 200, 250, 300, 400, 500, "ALL"]
        self.geo_cache = {}
        self.output_dir = "configs-flagged"
        self.source_dir = "configs.txt/combined"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.country_configs = defaultdict(lambda: defaultdict(list))
        self.all_flagged_configs = []

    def get_country_by_ip(self, ip):
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        services = [
            f"https://ipapi.co/{ip}/country/",
            f"https://ipinfo.io/{ip}/country",
            f"https://api.ipregistry.co/{ip}?key=tryout"
        ]
        
        for service in services:
            try:
                r = self.session.get(service, timeout=5)
                if r.status_code == 200:
                    if 'ipapi.co' in service:
                        code = r.text.strip().lower()
                    elif 'ipinfo.io' in service:
                        code = r.text.strip().lower()
                    elif 'ipregistry.co' in service:
                        data = r.json()
                        code = data.get('location', {}).get('country', {}).get('code', 'unknown').lower()
                    else:
                        code = 'unknown'
                    
                    if code and code != 'unknown' and len(code) == 2:
                        self.geo_cache[ip] = code
                        return code
            except:
                continue
            time.sleep(0.5)
        
        self.geo_cache[ip] = "unknown"
        return "unknown"

    def country_flag(self, code):
        if not code or code == "unknown":
            return "🏳️"
        code = code.strip().upper()
        if len(code) != 2 or not code.isalpha():
            return "🏳️"
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

    def is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except:
            return False

    def resolve_host(self, host):
        host = host.strip()
        if not host:
            return host
        if self.is_ip(host):
            return host
        try:
            return socket.gethostbyname(host)
        except:
            return host

    def extract_host_port(self, config_str):
        try:
            if config_str.startswith('vmess://'):
                try:
                    decoded = base64.b64decode(config_str.replace('vmess://', '')).decode('utf-8')
                    cfg = json.loads(decoded)
                    return cfg.get('add', ''), str(cfg.get('port', ''))
                except:
                    pass
            elif config_str.startswith('ss://'):
                raw = config_str.replace('ss://', '').split('#')[0]
                if '@' in raw:
                    _, hostport = raw.split('@', 1)
                    if ':' in hostport:
                        host, port = hostport.rsplit(':', 1)
                        return host, port
                try:
                    decoded = base64.b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8')
                    if '@' in decoded:
                        _, hostport = decoded.split('@', 1)
                        if ':' in hostport:
                            host, port = hostport.rsplit(':', 1)
                            return host, port
                except:
                    pass
            elif config_str.startswith('ssr://'):
                raw = config_str.replace('ssr://', '')
                decoded = base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)).decode('utf-8', errors='ignore')
                parts = decoded.split('/?', 1)[0].split(':')
                if len(parts) >= 2:
                    return parts[0], parts[1]
            else:
                parsed = urlparse(config_str)
                netloc = parsed.netloc
                if '@' in netloc:
                    netloc = netloc.split('@', 1)[1]
                if ':' in netloc:
                    host, port = netloc.rsplit(':', 1)
                    return host, port
                return netloc, ''
        except:
            pass
        return '', ''

    def get_original_tag(self, config_str):
        try:
            if config_str.startswith('vmess://'):
                decoded = base64.b64decode(config_str.replace('vmess://', '')).decode('utf-8')
                cfg = json.loads(decoded)
                return cfg.get('ps', '')
            elif '#' in config_str:
                return unquote(config_str.split('#', 1)[1])
            return ''
        except:
            return ''

    def flag_config(self, config_str):
        try:
            host, port = self.extract_host_port(config_str)
            if not host:
                return config_str, 'unknown'
            
            ip = self.resolve_host(host)
            country = self.get_country_by_ip(ip)
            flag = self.country_flag(country)
            original_tag = self.get_original_tag(config_str)
            
            if original_tag:
                new_tag = f"{flag} {original_tag}"
            else:
                new_tag = f"{flag} Config"
            
            flagged_config = config_str
            if config_str.startswith('vmess://'):
                try:
                    decoded = base64.b64decode(config_str.replace('vmess://', '')).decode('utf-8')
                    cfg = json.loads(decoded)
                    cfg['ps'] = new_tag
                    flagged_config = 'vmess://' + base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode()).decode()
                except:
                    pass
            elif '#' in config_str:
                base = config_str.split('#', 1)[0]
                flagged_config = f"{base}#{quote(new_tag)}"
            else:
                flagged_config = f"{config_str}#{quote(new_tag)}"
            
            return flagged_config, country
        except:
            return config_str, 'unknown'

    def read_config_file(self, filepath):
        if not os.path.exists(filepath):
            return []
        configs = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
        return configs

    def write_config_file(self, filepath, title, configs, count, timestamp):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        content = f"# {title}\n"
        content += f"# Updated: {timestamp}\n"
        content += f"# Count: {count}\n\n"
        content += "\n".join(configs)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

    def process_source(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        os.makedirs(self.output_dir, exist_ok=True)

        for category in self.categories:
            cat_dir = os.path.join(self.source_dir, category)
            if not os.path.exists(cat_dir):
                continue

            tier_files = {}
            for tier_file in os.listdir(cat_dir):
                if tier_file.endswith('.txt'):
                    filepath = os.path.join(cat_dir, tier_file)
                    configs = self.read_config_file(filepath)
                    if configs:
                        tier_name = tier_file.replace('.txt', '')
                        tier_files[tier_name] = configs

            if not tier_files:
                continue

            output_cat_dir = os.path.join(self.output_dir, category)
            os.makedirs(output_cat_dir, exist_ok=True)

            for tier_name, configs in tier_files.items():
                flagged_configs = []
                for config in configs:
                    flagged, country = self.flag_config(config)
                    flagged_configs.append(flagged)
                    self.all_flagged_configs.append(flagged)
                    if country != 'unknown':
                        self.country_configs[country][category].append(flagged)

                output_filename = os.path.join(output_cat_dir, f"{tier_name}.txt")
                title = f"Flagged {category.upper()} - Tier {tier_name}"
                self.write_config_file(output_filename, title, flagged_configs, len(flagged_configs), timestamp)

        self.process_all_tiers(timestamp)
        self.process_country_folders(timestamp)

    def process_all_tiers(self, timestamp):
        all_dir = os.path.join(self.source_dir, 'ALL')
        if not os.path.exists(all_dir):
            return

        output_all_dir = os.path.join(self.output_dir, 'ALL')
        os.makedirs(output_all_dir, exist_ok=True)

        for tier_file in os.listdir(all_dir):
            if tier_file.endswith('.txt'):
                filepath = os.path.join(all_dir, tier_file)
                configs = self.read_config_file(filepath)
                if not configs:
                    continue

                tier_name = tier_file.replace('.txt', '')
                flagged_configs = []
                for config in configs:
                    flagged, country = self.flag_config(config)
                    flagged_configs.append(flagged)
                    self.all_flagged_configs.append(flagged)
                    if country != 'unknown':
                        self.country_configs[country]['ALL'].append(flagged)

                output_filename = os.path.join(output_all_dir, f"{tier_name}.txt")
                title = f"Flagged ALL - Tier {tier_name}"
                self.write_config_file(output_filename, title, flagged_configs, len(flagged_configs), timestamp)

    def process_country_folders(self, timestamp):
        country_output_dir = os.path.join(self.output_dir, 'by_country')
        os.makedirs(country_output_dir, exist_ok=True)

        for country, categories in self.country_configs.items():
            country_dir = os.path.join(country_output_dir, country)
            os.makedirs(country_dir, exist_ok=True)

            all_country_configs = []
            for category, configs in categories.items():
                if configs:
                    filename = os.path.join(country_dir, f"{category}.txt")
                    title = f"Country {country.upper()} - {category.upper()}"
                    self.write_config_file(filename, title, configs, len(configs), timestamp)
                    all_country_configs.extend(configs)

            if all_country_configs:
                filename = os.path.join(country_dir, "all.txt")
                title = f"Country {country.upper()} - ALL"
                self.write_config_file(filename, title, all_country_configs, len(all_country_configs), timestamp)

        if self.all_flagged_configs:
            filename = os.path.join(self.output_dir, "all_flagged.txt")
            title = "All Flagged Configs"
            self.write_config_file(filename, title, self.all_flagged_configs, len(self.all_flagged_configs), timestamp)

    def run(self):
        print("=" * 60)
        print("CONFIG FLAGGER WITH COUNTRY DETECTION")
        print("=" * 60)
        print(f"Input directory: {self.source_dir}")
        print(f"Output directory: {self.output_dir}")
        print("-" * 60)

        try:
            self.process_source()
            print(f"\n✅ Flagged configs saved to {self.output_dir}/")
            print(f"✅ Country-based configs saved to {self.output_dir}/by_country/")
            
            if self.country_configs:
                print(f"\n📊 Countries detected: {len(self.country_configs)}")
                for country in sorted(self.country_configs.keys()):
                    total = sum(len(c) for c in self.country_configs[country].values())
                    print(f"  {self.country_flag(country)} {country.upper()}: {total} configs")
            else:
                print("\n⚠️ No countries detected! Check your internet connection or API access.")
                
        except Exception as e:
            print(f"\n❌ ERROR: {e}")

def main():
    flagger = ConfigFlagger()
    flagger.run()

if __name__ == "__main__":
    main()
