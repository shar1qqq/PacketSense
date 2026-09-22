"""
chatbot.py

Loads flow data from a pcap (same parsing as pipeline.py), builds it into
a single block of context, and starts an interactive chat where you can
ask plain-English questions about your own captured traffic.

This is different from ai_explainer.py: that file explains individual
flagged flows one at a time. This file gives the AI the WHOLE picture at
once, so it can answer comparative/summary questions across every flow
("which IP sent the most data", "how many things looked suspicious",
"walk me through what happened here").

Usage:
    python3 chatbot.py sample.pcap
"""

import sys

from dotenv import load_dotenv
from anthropic import Anthropic

from capture import run_tshark_conversations, parse_conversations
from rules import evaluate_flow

load_dotenv()

MODEL = "claude-sonnet-4-5"

SYSTEM_PROMPT_TEMPLATE = """You are a network traffic assistant helping a \
beginner understand a packet capture. You have been given the full list of \
network flows from their capture below, including which ones a rule-based \
system flagged as suspicious and why.

Answer their questions using ONLY this data. Explain things in plain, \
non-jargon English. If they ask about something not in the data, say so \
instead of guessing.

CAPTURED FLOW DATA:
{flow_context}
"""


def load_flows(pcap_path):
    """Same parsing pipeline.py uses -- pulls flows out of a pcap via tshark."""
    all_flows = []
    for protocol in ("tcp", "udp"):
        raw = run_tshark_conversations(pcap_path, protocol)
        all_flows.extend(parse_conversations(raw, protocol))
    return all_flows


def build_flow_context(flows):
    """
    Turns every flow into a compact text block the AI can read as
    context. Every flow is included, not just flagged ones, so the
    chatbot can answer questions about "normal" traffic too.
    """
    lines = []
    for i, flow in enumerate(flows, start=1):
        reasons = evaluate_flow(flow)
        flag_text = "; ".join(reasons) if reasons else "none"
        lines.append(
            f"{i}. {flow['src_ip']} -> {flow['dst_ip']}:{flow['dst_port']} "
            f"({flow['protocol']}) | packets={flow['packet_count']} "
            f"bytes={flow['total_bytes']} duration={flow['duration_seconds']}s "
            f"| rule flags: {flag_text}"
        )
    return "\n".join(lines)


def run_chat(pcap_path):
    flows = load_flows(pcap_path)
    if not flows:
        print(f"No flows found in {pcap_path}.")
        return

    flow_context = build_flow_context(flows)
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(flow_context=flow_context)

    client = Anthropic()
    conversation = []  # holds the back-and-forth so the AI remembers earlier questions

    print(f"Loaded {len(flows)} flows from {pcap_path}.")
    print("Ask anything about this capture. Type 'exit' to quit.\n")

    while True:
        user_input = input("You: ").strip()
        if user_input.lower() in ("exit", "quit"):
            break
        if not user_input:
            continue

        conversation.append({"role": "user", "content": user_input})

        response = client.messages.create(
            model=MODEL,
            max_tokens=500,
            system=system_prompt,
            messages=conversation,
        )

        reply_text = response.content[0].text
        print(f"\nAI: {reply_text}\n")

        conversation.append({"role": "assistant", "content": reply_text})


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 chatbot.py <path-to-pcap-file>")
        sys.exit(1)

    run_chat(sys.argv[1])
