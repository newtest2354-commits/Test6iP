import os
import re
import json
import base64
import yaml
import hashlib
import uuid
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime

class YAMLConverter:
    def __init__(self):
        self.categories = [
            'vmess', 'vless', 'trojan', 'ss',
            'hysteria2', 'hysteria', 'tuic',
            'wireguard', 'other'
        ]
        self.tiers = [50, 100, 150, 200, 250, 300, 400, 500, "ALL"]
        self.output_dir = "configs/yaml"
    
    def get_original_tag(self, config_url):
        try:
            if config_url.startswith("ss://"):
                parts = config_url.split('#')
                if len(parts) > 1:
                    return unquote(parts[1]) or ""
                return ""
            elif config_url.startswith("hysteria2://") or config_url.startswith("hy2://"):
                url = urlparse(config_url)
                return unquote(url.fragment) or ""
            elif config_url.startswith("vmess://"):
                try:
                    decoded = base64.b64decode(config_url.replace('vmess://', '')).decode('utf-8')
                    vmess_config = json.loads(decoded)
                    return vmess_config.get('ps', "")
                except:
                    return ""
            elif config_url.startswith("trojan://"):
                url = urlparse(config_url)
                return unquote(url.fragment) or ""
            else:
                url = urlparse(config_url)
                return unquote(url.fragment) or ""
        except:
            return ""
    
    def decode_ss_config(self, ss_url):
        try:
            if not ss_url.startswith('ss://'):
                return None
            
            if ss_url.startswith('ss://{'):
                return None
            
            parts = ss_url.split('#', 1)
            encoded_part = parts[0][5:]
            
            if '@' not in encoded_part:
                return None
            
            method_password, server_port = encoded_part.split('@', 1)
            
            if len(method_password) % 4 != 0:
                method_password += '=' * (4 - len(method_password) % 4)
            
            decoded_method_password = base64.b64decode(method_password).decode('utf-8')
            if ':' not in decoded_method_password:
                return None
            
            method, password = decoded_method_password.split(':', 1)
            
            if not server_port or not method or not password:
                return None
            
            if ':' not in server_port:
                return None
            
            server, port_str = server_port.split(':', 1)
            
            try:
                port = int(port_str)
            except:
                port = 443
            
            name = ""
            if len(parts) > 1:
                name = unquote(parts[1])
            
            return {
                'method': method,
                'password': password,
                'server': server,
                'port': port,
                'name': name
            }
        except Exception as e:
            return None
    
    def decode_vmess_config(self, vmess_url):
        try:
            base64_data = vmess_url.replace('vmess://', '')
            if len(base64_data) % 4 != 0:
                base64_data += '=' * (4 - len(base64_data) % 4)
            decoded = base64.b64decode(base64_data).decode('utf-8')
            config = json.loads(decoded)
            return config
        except Exception as e:
            return None
    
    def vless_to_clashmeta(self, url_str, index):
        try:
            url = urlparse(url_str)
            params = parse_qs(url.query)
            params = {k: v[0] if v else None for k, v in params.items()}
            
            if params.get('security') == 'reality':
                if not params.get('pbk') or not params.get('pbk').strip():
                    return None
            
            original_name = self.get_original_tag(url_str) or "VLESS"
            config_name = f"{original_name} #{index + 1}"
            
            network_type = params.get('type', 'tcp')
            tls_enabled = params.get('security') in ['tls', 'reality']
            final_server = url.hostname
            final_sni = params.get('sni') or params.get('host') or url.hostname
            
            config = {
                'name': config_name,
                'type': 'vless',
                'server': final_server,
                'port': int(url.port) if url.port else 443,
                'uuid': url.username,
                'network': network_type,
                'tls': tls_enabled,
                'udp': True,
                'skip-cert-verify': False,
                'tcp-fast-open': True,
                'servername': final_sni,
                'client-fingerprint': 'chrome'
            }
            
            if params.get('flow'):
                config['flow'] = params['flow']
            
            if params.get('packet-encoding'):
                config['packet-encoding'] = params['packet-encoding']
            
            if tls_enabled:
                config['alpn'] = ['h2', 'http/1.1']
            
            if network_type == 'ws':
                config['ws-opts'] = {
                    'path': params.get('path', '/'),
                    'headers': {
                        'Host': params.get('host', final_sni)
                    },
                    'max-early-data': int(params.get('maxEarlyData')) if params.get('maxEarlyData') else 2048,
                    'early-data-header-name': params.get('earlyDataHeaderName', 'Sec-WebSocket-Protocol')
                }
            
            if network_type == 'grpc':
                if params.get('serviceName'):
                    config['grpc-opts'] = {
                        'grpc-service-name': params['serviceName']
                    }
            
            if network_type == 'http':
                config['http-opts'] = {
                    'method': params.get('method', 'GET'),
                    'path': [params.get('path', '/')],
                    'headers': {
                        'Host': [params.get('host', final_sni)]
                    }
                }
            
            if params.get('security') == 'reality' and params.get('pbk'):
                config['reality-opts'] = {
                    'public-key': params['pbk']
                }
                if params.get('sid'):
                    sid = params['sid']
                    if re.match(r'^[0-9a-fA-F]{2,16}$', sid):
                        config['reality-opts']['short-id'] = sid.lower()
            
            return config
        except Exception as e:
            return None
    
    def ss_to_clashmeta(self, ss_url, index):
        decoded = self.decode_ss_config(ss_url)
        if not decoded:
            return None
        
        original_name = decoded.get('name') or "Shadowsocks"
        config_name = f"{original_name} #{index + 1}"
        
        allowed_ciphers = [
            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
            "aes-128-cfb", "aes-256-cfb", "chacha20", "chacha20-ietf"
        ]
        
        cipher = decoded['method'] if decoded['method'] in allowed_ciphers else None
        if not cipher:
            return None
        
        return {
            'name': config_name,
            'type': 'ss',
            'server': decoded['server'],
            'port': decoded['port'],
            'cipher': cipher,
            'password': decoded['password'],
            'udp': True,
            'tcp-fast-open': True
        }
    
    def hysteria2_to_clashmeta(self, url_str, index):
        try:
            url_str_normalized = url_str.replace('hy2://', 'hysteria2://') if url_str.startswith('hy2://') else url_str
            url = urlparse(url_str_normalized)
            params = parse_qs(url.query)
            params = {k: v[0] if v else None for k, v in params.items()}
            
            original_name = self.get_original_tag(url_str) or "Hysteria2"
            config_name = f"{original_name} #{index + 1}"
            
            config = {
                'name': config_name,
                'type': 'hysteria2',
                'server': url.hostname,
                'port': int(url.port) if url.port else 443,
                'password': url.username or "",
                'sni': url.hostname,
                'skip-cert-verify': False,
                'fast-open': True,
                'client-fingerprint': 'chrome'
            }
            
            if params.get('obfs') and params.get('obfs-password'):
                config['obfs'] = params['obfs']
                config['obfs-password'] = params['obfs-password']
            
            if params.get('up') or params.get('down'):
                config['up'] = params.get('up', '100 Mbps')
                config['down'] = params.get('down', '100 Mbps')
            
            if params.get('ports'):
                config['ports'] = params['ports']
            
            return config
        except Exception as e:
            return None
    
    def vmess_to_clashmeta(self, vmess_url, index):
        try:
            vmess_config = self.decode_vmess_config(vmess_url)
            if not vmess_config:
                return None
            
            def sanitize(s):
                if not s:
                    return ""
                s = str(s)
                s = re.sub(r'[\u0000-\u001F\u007F-\u009F]', '', s)
                s = re.sub(r'[^\x20-\x7E\u0600-\u06FF]', '', s)
                s = re.sub(r'\s+', ' ', s)
                return s.strip()
            
            original_name = sanitize(vmess_config.get('ps', "VMess"))
            config_name = f"{original_name} #{index + 1}"
            
            network_type = vmess_config.get('net', 'tcp')
            tls_enabled = vmess_config.get('tls') == 'tls'
            
            config = {
                'name': config_name,
                'type': 'vmess',
                'server': vmess_config.get('add'),
                'port': int(vmess_config.get('port')) if vmess_config.get('port') else 443,
                'uuid': vmess_config.get('id'),
                'alterId': int(vmess_config.get('aid')) if vmess_config.get('aid') else 0,
                'cipher': vmess_config.get('scy', 'auto'),
                'network': network_type,
                'tls': tls_enabled,
                'udp': True,
                'skip-cert-verify': False,
                'tcp-fast-open': True,
                'servername': vmess_config.get('sni') or vmess_config.get('add'),
                'client-fingerprint': 'chrome'
            }
            
            if tls_enabled:
                config['alpn'] = ['h2', 'http/1.1']
            
            if network_type == 'ws':
                config['ws-opts'] = {
                    'path': vmess_config.get('path', '/'),
                    'headers': {
                        'Host': vmess_config.get('host') or vmess_config.get('add')
                    }
                }
            
            if network_type == 'h2':
                config['h2-opts'] = {
                    'host': [vmess_config.get('host') or vmess_config.get('add')],
                    'path': vmess_config.get('path', '/')
                }
            
            if network_type == 'grpc':
                config['grpc-opts'] = {
                    'grpc-service-name': vmess_config.get('path', 'GunService')
                }
            
            return config
        except Exception as e:
            return None
    
    def trojan_to_clashmeta(self, trojan_url, index):
        try:
            url = urlparse(trojan_url)
            params = parse_qs(url.query)
            params = {k: v[0] if v else None for k, v in params.items()}
            
            original_name = self.get_original_tag(trojan_url) or "Trojan"
            config_name = f"{original_name} #{index + 1}"
            
            network_type = params.get('type', 'tcp')
            
            config = {
                'name': config_name,
                'type': 'trojan',
                'server': url.hostname,
                'port': int(url.port) if url.port else 443,
                'password': url.username,
                'network': network_type,
                'udp': True,
                'skip-cert-verify': False,
                'tcp-fast-open': True,
                'servername': params.get('sni') or params.get('host') or url.hostname,
                'client-fingerprint': 'chrome'
            }
            
            if network_type == 'grpc':
                config['grpc-opts'] = {
                    'grpc-service-name': params.get('serviceName', 'GunService')
                }
            
            if network_type == 'ws':
                config['ws-opts'] = {
                    'path': params.get('path', '/'),
                    'headers': {
                        'Host': params.get('sni') or url.hostname
                    }
                }
            
            return config
        except Exception as e:
            return None
    
    def convert_config(self, config_url, index):
        if config_url.startswith('vmess://'):
            return self.vmess_to_clashmeta(config_url, index)
        elif config_url.startswith('vless://'):
            return self.vless_to_clashmeta(config_url, index)
        elif config_url.startswith('trojan://'):
            return self.trojan_to_clashmeta(config_url, index)
        elif config_url.startswith('ss://'):
            return self.ss_to_clashmeta(config_url, index)
        elif config_url.startswith('hysteria2://') or config_url.startswith('hy2://'):
            return self.hysteria2_to_clashmeta(config_url, index)
        else:
            return None
    
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
    
    def process_category(self, source_name, category, configs):
        if not configs:
            return
        
        os.makedirs(os.path.join(self.output_dir, source_name, category), exist_ok=True)
        
        total_configs = len(configs)
        
        for tier in self.tiers:
            if tier != "ALL" and tier > total_configs:
                continue
            
            if tier == "ALL":
                selected_configs = configs
            else:
                selected_configs = configs[:tier]
            
            yaml_configs = []
            for i, config in enumerate(selected_configs):
                converted = self.convert_config(config, i)
                if converted:
                    yaml_configs.append(converted)
            
            if not yaml_configs:
                continue
            
            filename = os.path.join(self.output_dir, source_name, category, f"{tier}.yaml")
            content = {
                'proxies': yaml_configs,
                'total': len(yaml_configs),
                'source': source_name,
                'category': category,
                'tier': str(tier)
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                yaml.dump(content, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    def process_combined_all(self, combined_configs):
        if not combined_configs:
            return
        
        os.makedirs(os.path.join(self.output_dir, 'combined', 'ALL'), exist_ok=True)
        total_configs = len(combined_configs)
        
        for tier in self.tiers:
            if tier != "ALL" and tier > total_configs:
                continue
            
            if tier == "ALL":
                selected_configs = combined_configs
            else:
                selected_configs = combined_configs[:tier]
            
            yaml_configs = []
            for i, config in enumerate(selected_configs):
                converted = self.convert_config(config, i)
                if converted:
                    yaml_configs.append(converted)
            
            if not yaml_configs:
                continue
            
            filename = os.path.join(self.output_dir, 'combined', 'ALL', f"{tier}.yaml")
            content = {
                'proxies': yaml_configs,
                'total': len(yaml_configs),
                'source': 'combined',
                'category': 'ALL',
                'tier': str(tier)
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                yaml.dump(content, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    def convert_all(self):
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        print("=" * 60)
        print("YAML CONVERTER")
        print("=" * 60)
        
        for source_name in ['telegram', 'github', 'combined']:
            base_dir = os.path.join('configs', source_name)
            if not os.path.exists(base_dir):
                continue
            
            for category in self.categories:
                category_dir = os.path.join(base_dir, category)
                if not os.path.exists(category_dir) or not os.path.isdir(category_dir):
                    continue
                
                all_configs = []
                all_file = os.path.join(category_dir, 'ALL.txt')
                if os.path.exists(all_file):
                    all_configs = self.read_config_file(all_file)
                
                if all_configs:
                    print(f"Processing {source_name}/{category} ({len(all_configs)} configs)")
                    self.process_category(source_name, category, all_configs)
            
            all_dir = os.path.join(base_dir, 'ALL')
            if os.path.exists(all_dir) and os.path.isdir(all_dir):
                all_file = os.path.join(all_dir, 'ALL.txt')
                if os.path.exists(all_file):
                    combined_configs = self.read_config_file(all_file)
                    if combined_configs:
                        print(f"Processing combined/{source_name}/ALL ({len(combined_configs)} configs)")
                        if source_name == 'combined':
                            self.process_combined_all(combined_configs)
                        else:
                            self.process_category(source_name, 'ALL', combined_configs)
        
        print("\n" + "=" * 60)
        print("YAML CONVERSION COMPLETE")
        print("=" * 60)
        
        for root, dirs, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith('.yaml'):
                    filepath = os.path.join(root, file)
                    rel_path = os.path.relpath(filepath, self.output_dir)
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        count = data.get('total', 0) if data else 0
                    print(f"  {rel_path}: {count} proxies")
        
        print("=" * 60)

def main():
    converter = YAMLConverter()
    converter.convert_all()

if __name__ == "__main__":
    main()
