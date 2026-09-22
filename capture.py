"""
capture.py

Runs tshark against a pcap file (or a live interface), turns its
conversation summary into the flow format rules.py expects, and
prints which flows get flagged.

This is the piece that connects "real network data" to the detection
logic you already wrote in rules.py.

Usage:
    python3 capture.py sample.pcap
"""

import re
import subprocess
import sys

from rules import evaluate_flow

# Matches a line like:
# 192.168.1.10:52345   <-> 142.250.80.14:443   0 0 bytes   6 324 bytes   6 324 bytes   0.000000000   0.0009
CONV_LINE_PATTERN = re.compile(
    r"^\s*(\S+)\s+<->\s+(\S+)\s+"          # source <-> destination
    r"(\d+)\s+(\d+)\s+bytes\s+"            # frames back, bytes back
    r"(\d+)\s+(\d+)\s+bytes\s+"            # frames forward, bytes forward
    r"(\d+)\s+(\d+)\s+bytes\s+"            # total frames, total bytes
    r"([\d.]+)\s+([\d.]+)\s*$"             # relative start, duration
)


def run_tshark_conversations(pcap_path, protocol):
    """
    protocol should be 'tcp' or 'udp'.
    Returns the raw text tshark prints for that conversation table.
    """
    result = subprocess.run(
        ["tshark", "-q", "-z", f"conv,{protocol}", "-r", pcap_path],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def parse_conversations(raw_text, protocol):
    """
    Turns tshark's text table into a list of flow dicts matching
    the format rules.py expects.
    """
    flows = []

    for line in raw_text.splitlines():
        match = CONV_LINE_PATTERN.match(line)
        if not match:
            continue  # skip headers, separators, blank lines

        src, dst, frames_back, bytes_back, frames_fwd, bytes_fwd, \
            total_frames, total_bytes, start, duration = match.groups()

        src_ip, src_port = src.rsplit(":", 1)
        dst_ip, dst_port = dst.rsplit(":", 1)

        flow = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),
            "protocol": protocol.upper(),
            "packet_count": int(total_frames),
            "total_bytes": int(total_bytes),
            "duration_seconds": float(duration),
            # Simplification: if nothing came back in the reply direction,
            # treat it like a SYN-with-no-reply pattern. Not a perfect
            # TCP-flag check, but a reasonable stand-in for a portfolio
            # project -- worth mentioning as a known limitation.
            "syn_no_reply": (protocol == "tcp" and int(frames_back) == 0),
        }
        flows.append(flow)

    return flows


def analyze_pcap(pcap_path):
    all_flows = []

    for protocol in ("tcp", "udp"):
        raw = run_tshark_conversations(pcap_path, protocol)
        all_flows.extend(parse_conversations(raw, protocol))

    print(f"Parsed {len(all_flows)} flows from {pcap_path}\n")

    for flow in all_flows:
        reasons = evaluate_flow(flow)
        status = "FLAGGED" if reasons else "normal"
        print(f"[{status}] {flow['src_ip']} -> {flow['dst_ip']}:{flow['dst_port']} "
              f"({flow['protocol']}, {flow['packet_count']} pkts, {flow['total_bytes']} bytes)")
        for reason in reasons:
            print(f"    - {reason}")

    return all_flows


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 capture.py <path-to-pcap-file>")
        sys.exit(1)

    analyze_pcap(sys.argv[1])
