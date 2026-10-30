"""Safe, test-only Suricata alert rule proposal generator."""

from ipaddress import ip_address, ip_network

# Documentation-only IPv4 networks (RFC 5737).
TEST_NETWORKS = (
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
)


def _test_ip(value):
    if not isinstance(value, str):
        raise ValueError("IP address must be a string")

    address = ip_address(value)

    if address.version != 4:
        raise ValueError("Only IPv4 is supported in this prototype")

    if not any(address in network for network in TEST_NETWORKS):
        raise ValueError(
            "Prototype accepts documentation-only IP addresses"
        )

    return str(address)


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    return value


def build_test_alert_rule(
    *,
    protocol,
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    sid,
):
    if not isinstance(protocol, str):
        raise ValueError("Invalid protocol")

    protocol = protocol.lower()

    if protocol not in {"tcp", "udp"}:
        raise ValueError("Only TCP/UDP are supported")

    src = _test_ip(source_ip)
    dst = _test_ip(destination_ip)
    sport = _port(source_port)
    dport = _port(destination_port)

    if type(sid) is not int or not 1 <= sid <= 4294967295:
        raise ValueError("Invalid SID")

    return (
        f"alert {protocol} {src} {sport} -> {dst} {dport} "
        f'(msg:"LOCAL TEST CANDIDATE - NOT VERIFIED ATTACK"; '
        f"sid:{sid}; rev:1;)"
    )

def build_syn_burst_review_rule(
    *, destination_ip, normal_max_syn, window_seconds=10, sid=9102001
):
    """Review-only SYN packet-count proxy, not a learned model rule."""
    address = ip_address(destination_ip)

    if address.version != 4:
        raise ValueError("IPv4 required")
    if type(normal_max_syn) is not int or normal_max_syn < 0:
        raise ValueError("Invalid Normal maximum")
    if type(window_seconds) is not int or window_seconds != 10:
        raise ValueError("Window contract mismatch")
    if type(sid) is not int or not 1 <= sid <= 4294967295:
        raise ValueError("Invalid SID")

    count = max(3, normal_max_syn + 1)

    return (
        f"alert tcp any any -> {address} any "
        '(msg:"LAB AI REVIEW SYN burst proxy"; '
        "flow:stateless; tcp.flags:S,CE; "
        "threshold:type threshold,track by_both,"
        f"count {count},seconds {window_seconds}; "
        f"classtype:attempted-recon; sid:{sid}; rev:1;)"
    )
