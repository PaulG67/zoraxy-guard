from __future__ import annotations

import ipaddress
from typing import Iterable, List, Set, Union

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def parse_ip(value: str) -> IpAddress | None:
    value = value.strip().strip("[]")
    if not value:
        return None
    # Strip :port for weird clients (IPv4 only safe split)
    if value.count(":") == 1 and "." in value:
        value = value.split(":", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def parse_network(value: str) -> IpNetwork | None:
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    try:
        if "/" not in value:
            ip = ipaddress.ip_address(value)
            return ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def load_networks(items: Iterable) -> List[IpNetwork]:
    nets: List[IpNetwork] = []
    for item in items or []:
        if item is None or item == []:
            continue
        if isinstance(item, (list, dict)):
            continue
        net = parse_network(str(item))
        if net:
            nets.append(net)
    return nets


def load_networks_file(path: str) -> List[IpNetwork]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return load_networks(line.strip() for line in fh if line.strip())
    except FileNotFoundError:
        return []


def ip_in_networks(ip: IpAddress, networks: Iterable[IpNetwork]) -> bool:
    for net in networks:
        try:
            if ip.version == net.version and ip in net:
                return True
        except Exception:
            continue
    return False


def merge_ip_set_from_feed_text(text: str) -> Set[str]:
    result: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        # ipsum sometimes: "1.2.3.4 # comment"
        token = line.split()[0]
        if parse_ip(token) or parse_network(token):
            result.add(token)
    return result