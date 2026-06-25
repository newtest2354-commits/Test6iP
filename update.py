import json
import ipaddress
import requests

RIPE_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{}"

with open("asn.json", "r", encoding="utf-8") as f:
    ASNS = json.load(f)["asns"]

prefixes = set()

for asn in ASNS:
    try:
        r = requests.get(
            RIPE_URL.format(asn),
            timeout=30
        )

        r.raise_for_status()

        data = r.json()

        for item in data["data"]["prefixes"]:
            prefix = item["prefix"]

            if ":" in prefix:
                continue

            try:
                ipaddress.ip_network(prefix)
                prefixes.add(prefix)
            except Exception:
                pass

    except Exception as e:
        print(f"AS{asn}: {e}")

prefixes = sorted(
    prefixes,
    key=lambda x: (
        int(ipaddress.ip_network(x).network_address),
        ipaddress.ip_network(x).prefixlen
    )
)

with open(
    "ipv4-aggregated.txt",
    "w",
    encoding="utf-8"
) as f:
    f.write("\n".join(prefixes))
