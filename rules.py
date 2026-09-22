"""
rules.py

This file contains simple, human-readable rules for flagging suspicious
network flows. No AI here yet -- just logic. This is the "detection" layer.
Later, only flows that get flagged by these rules will be sent to the AI
for a plain-English explanation.

A "flow" here is just a dictionary describing one conversation between
two devices, built from packet data. Example of what a flow looks like:

flow = {
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "dst_port": 443,
    "protocol": "TCP",
    "packet_count": 12,
    "total_bytes": 1500,
    "duration_seconds": 2.3,
    "syn_no_reply": False,
}
"""

# Ports that are common/expected for normal traffic.
# Anything outside this set is not automatically bad, just worth a second look.
COMMON_PORTS = {80, 443, 53, 22, 25, 110, 143, 993, 995}

# Thresholds you can tune as you learn more about what "normal" looks like
# on your own test network.
MAX_NORMAL_PACKET_SIZE = 1500      # bytes, roughly typical Ethernet MTU
MIN_SUSPICIOUS_CONNECTIONS = 20    # connections from one source in the window
LARGE_FLOW_BYTES = 1_000_000       # 1 MB, arbitrary starting point


def check_unusual_port(flow):
    """Flag traffic going to a port outside the common set."""
    if flow["dst_port"] not in COMMON_PORTS:
        return f"Unusual destination port: {flow['dst_port']}"
    return None


def check_large_transfer(flow):
    """Flag flows that moved an unusually large amount of data."""
    if flow["total_bytes"] > LARGE_FLOW_BYTES:
        return f"Large data transfer: {flow['total_bytes']} bytes"
    return None


def check_syn_scan_pattern(flow):
    """Flag a classic port-scan signature: SYN sent, no reply."""
    if flow.get("syn_no_reply"):
        return "SYN sent with no reply (possible port scan behavior)"
    return None


def check_high_connection_rate(source_ip_counts, flow):
    """
    Flag a source IP making a lot of separate connections quickly.
    source_ip_counts is a dict you build elsewhere: {ip: count}.
    """
    count = source_ip_counts.get(flow["src_ip"], 0)
    if count > MIN_SUSPICIOUS_CONNECTIONS:
        return f"High connection rate from {flow['src_ip']}: {count} connections"
    return None


# All the individual checks, run in order. Easy to add more later.
RULES = [
    check_unusual_port,
    check_large_transfer,
    check_syn_scan_pattern,
]


def evaluate_flow(flow, source_ip_counts=None):
    """
    Run every rule against a single flow.
    Returns a list of reasons it was flagged (empty list = looks normal).
    """
    reasons = []

    for rule in RULES:
        result = rule(flow)
        if result:
            reasons.append(result)

    if source_ip_counts is not None:
        result = check_high_connection_rate(source_ip_counts, flow)
        if result:
            reasons.append(result)

    return reasons


if __name__ == "__main__":
    # Quick manual test so you can see it working without needing real
    # packet capture yet. Run: python rules.py
    test_flows = [
        {
            "src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "dst_port": 443,
            "protocol": "TCP", "packet_count": 12, "total_bytes": 1500,
            "duration_seconds": 2.3, "syn_no_reply": False,
        },
        {
            "src_ip": "192.168.1.10", "dst_ip": "45.33.32.156", "dst_port": 31337,
            "protocol": "TCP", "packet_count": 3, "total_bytes": 200,
            "duration_seconds": 0.1, "syn_no_reply": True,
        },
    ]

    for i, flow in enumerate(test_flows):
        flags = evaluate_flow(flow)
        status = "FLAGGED" if flags else "normal"
        print(f"Flow {i} ({flow['src_ip']} -> {flow['dst_ip']}:{flow['dst_port']}): {status}")
        for reason in flags:
            print(f"  - {reason}")
