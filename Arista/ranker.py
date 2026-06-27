def rank_results():
    data = load_results()
    domains_set = load_domains_raw()
    domains_ips = load_domains_ips()
    sni_map = load_tls_sni()
    city_map = load_geo_city()
    asn_map = load_geo_asn()
    tcp_map = load_tcp_latency()

    ranked = []

    for item in data:
        item["score"] = score(item)
        item["tcp"] = tcp_map.get(f"{item['ip']}:{item['port']}", 9999)
        ranked.append(item)

    existing_ips = {item['ip'] for item in ranked}

    for ip in domains_ips:
        if ip not in existing_ips:
            ranked.append({
                'ip': ip,
                'port': 443,
                'score': 5,
                'tcp': tcp_map.get(f"{ip}:443", 9999),
                'ttfb': 500,
                'proto': 'unknown',
                'reliability': 0.5,
                'cdn': 'unknown',
                'country': 'Unknown',
                'provider': 'Unknown'
            })

    ranked.sort(
        key=lambda x: (
            x.get("tcp", 9999),
            -x["score"],
            x.get("ttfb", 9999),
            x.get("port", 65535)
        )
    )

    os.makedirs("output", exist_ok=True)

    new_lines = []
    for item in ranked:
        ip = item["ip"]
        port = item["port"]
        key = f"{ip}:{port}"

        country = item.get("country", "-")
        provider = item.get("provider", "-")

        sni = sni_map.get(key, "-")
        tcp_latency = item.get("tcp", "N/A")

        if tcp_latency == 9999:
            tcp_display = "timeout"
        else:
            tcp_display = f"{tcp_latency}ms"

        city = city_map.get(ip, "-")
        asn = asn_map.get(ip, "")

        port_type = get_port_type(port)

        domain = "-"
        for d in sorted(domains_set):
            if d in sni or sni in d:
                domain = d
                break

        parts = [
            f'[IP: {ip}]',
            f'[PORT: {port}]',
            f'[SCORE={item["score"]}]',
            f'[TCP={tcp_display}]',
            f'[TTFB={item.get("ttfb", "-")}ms]',
            f'[PROTO={item.get("proto", "-")}]',
            f'[REL={item.get("reliability", "-")}]',
            f'[CDN={item.get("cdn", "-")}]',
            f'[TYPE={port_type}]'
        ]

        if domain and domain != "-":
            parts.append(f'[DOMAIN={domain}]')

        if sni and sni != "-":
            parts.append(f'[SNI={sni}]')

        if city and city != "-" and city != "Unknown":
            parts.append(f'[City={city}]')

        if country and country != "-" and country != "Unknown":
            parts.append(f'[Country={country}]')

        if provider and provider != "-" and provider != "Unknown":
            parts.append(f'[Provider={provider}]')

        if asn and asn != "Unknown":
            parts.append(f'[ASN={asn}]')

        line = " ".join(parts) + "\n"
        new_lines.append(line)

    print(f"[RANKER] NEW_IPS={len(new_lines)}")

    old_lines = []
    old_ips = {}

    if os.path.exists(BEST_FILE):
        try:
            with open(BEST_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parsed = parse_line_to_dict(line)
                    if parsed:
                        old_lines.append(line)
                        key = f"{parsed['ip']}:{parsed['port']}"
                        old_ips[key] = parsed
            print(f"[RANKER] LOADED {len(old_ips)} IPS FROM best_ips.txt")
        except Exception as e:
            print(f"[RANKER] ERROR READING best_ips.txt: {e}")
    else:
        print("[RANKER] best_ips.txt NOT FOUND - FIRST RUN")

    combined_dict = {}

    for line in new_lines:
        parsed = parse_line_to_dict(line)
        if parsed:
            key = f"{parsed['ip']}:{parsed['port']}"
            combined_dict[key] = parsed

    for key, parsed in old_ips.items():
        if key not in combined_dict:
            combined_dict[key] = parsed

    print(f"[RANKER] COMBINED_IPS={len(combined_dict)}")

    combined = sorted(
        combined_dict.values(),
        key=lambda x: (x["tcp"], -x["score"], x["ttfb"], x["port"])
    )

    combined_lines = [item["line"] for item in combined]

    unique_ips = set()
    unique_lines = []
    for line in combined_lines:
        if '[IP: ' in line:
            ip_match = line.split('[IP: ')[1].split(']')[0]
            if ip_match not in unique_ips:
                unique_ips.add(ip_match)
                unique_lines.append(line)
        else:
            unique_lines.append(line)

    combined_lines = unique_lines

    current_size_mb = get_file_size_mb(combined_lines)

    if current_size_mb > MAX_BEST_IPS_SIZE_MB:
        print(f"FILE SIZE {current_size_mb:.2f}MB EXCEEDED {MAX_BEST_IPS_SIZE_MB}MB! REMOVING WORST TCP ENTRIES...")
        while current_size_mb > MAX_BEST_IPS_SIZE_MB and len(combined_lines) > 100:
            removed = combined_lines.pop()
            current_size_mb = get_file_size_mb(combined_lines)
            print(f"REMOVED HIGH TCP ENTRY... NEW SIZE: {current_size_mb:.2f}MB")

    with open(BEST_FILE, "w", encoding="utf-8") as f:
        f.writelines(combined_lines)

    print(f"BEST_IPS_SIZE: {current_size_mb:.2f}MB")
    print(f"BEST_IPS_LINES: {len(combined_lines)}")
    print(f"RANKED={len(ranked)} DOMAINS={len(domains_set)} DOMAIN_IPS={len(domains_ips)}")
