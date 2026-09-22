"""
pipeline.py

The full pipeline, start to finish:
  1. Parse a pcap with tshark -> flows      (capture.py)
  2. Run every flow through rule-based checks    (rules.py)
  3. Send ONLY the flagged flows to the AI for a plain-English explanation
                                                (ai_explainer.py)
  4. Print a clean report

Usage:
    export ANTHROPIC_API_KEY="your-key-here"
    python3 pipeline.py sample.pcap
"""

import sys

from capture import run_tshark_conversations, parse_conversations
from rules import evaluate_flow
from ai_explainer import explain_flagged_flows


def main(pcap_path):
    all_flows = []
    for protocol in ("tcp", "udp"):
        raw = run_tshark_conversations(pcap_path, protocol)
        all_flows.extend(parse_conversations(raw, protocol))

    print(f"Parsed {len(all_flows)} flows from {pcap_path}")

    flagged = []
    for flow in all_flows:
        reasons = evaluate_flow(flow)
        if reasons:
            flagged.append((flow, reasons))

    print(f"{len(flagged)} flow(s) flagged by rules, sending to AI for explanation...\n")

    if not flagged:
        print("Nothing flagged. Traffic looks normal.")
        return

    results = explain_flagged_flows(flagged)

    for r in results:
        flow = r["flow"]
        ai = r["ai"]
        print(f"--- {flow['src_ip']} -> {flow['dst_ip']}:{flow['dst_port']} ({flow['protocol']}) ---")
        print(f"Threat level: {ai['threat_level']}")
        print(f"Why: {ai['explanation']}")
        print(f"Suggested action: {ai['recommended_action']}")
        print(f"(Rule triggers: {', '.join(r['rule_reasons'])})\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pipeline.py <path-to-pcap-file>")
        sys.exit(1)

    main(sys.argv[1])
