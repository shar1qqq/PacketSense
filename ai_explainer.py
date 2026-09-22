"""
ai_explainer.py

Takes flows that rules.py already flagged as suspicious, and asks an LLM
to explain them in plain English. Deliberately NOT called on every flow --
only on the ones the rule-based logic already flagged. That's what makes
this a pipeline instead of just "paste data into a chatbot."

Requires an Anthropic API key set as an environment variable:
    export ANTHROPIC_API_KEY="your-key-here"

Usage (standalone test):
    python3 ai_explainer.py
"""

import json
import os

from dotenv import load_dotenv
from anthropic import Anthropic

# Automatically reads a .env file in the project folder (if one exists)
# and loads ANTHROPIC_API_KEY from it, so you don't have to retype the
# export/$env: command every time you open a new terminal.
load_dotenv()

MODEL = "claude-sonnet-4-5"

# Asking for a fixed JSON structure instead of freeform chat text is what
# lets your program actually USE the AI's output programmatically --
# sort by severity, build a report, etc. -- rather than just displaying
# a paragraph.
SYSTEM_PROMPT = """You are a network security assistant. You will be given \
details about a flagged network flow and the rule-based reasons it was \
flagged. Explain in plain, non-jargon English what this traffic pattern \
might mean and how concerned a beginner should be.

Respond with ONLY a JSON object, no other text, in this exact format:
{
  "threat_level": "low" | "medium" | "high",
  "explanation": "1-2 plain-English sentences",
  "recommended_action": "1 short sentence"
}
"""


def build_flow_summary(flow, reasons):
    return (
        f"Source: {flow['src_ip']}\n"
        f"Destination: {flow['dst_ip']}:{flow['dst_port']}\n"
        f"Protocol: {flow['protocol']}\n"
        f"Packets: {flow['packet_count']}, Bytes: {flow['total_bytes']}, "
        f"Duration: {flow['duration_seconds']}s\n"
        f"Rule-based flags:\n" + "\n".join(f"- {r}" for r in reasons)
    )


def explain_flow(flow, reasons, client=None):
    """
    Sends one flagged flow to the LLM and returns a parsed dict:
    {threat_level, explanation, recommended_action}.

    Accepts an optional pre-built client so this function is easy to
    test without hitting the real API every time.
    """
    if client is None:
        client = Anthropic()  # reads ANTHROPIC_API_KEY from environment

    summary = build_flow_summary(flow, reasons)

    response = client.messages.create(
        model=MODEL,
        max_tokens=300,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": summary}],
    )

    raw_text = response.content[0].text

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        # LLMs occasionally wrap JSON in markdown fences despite instructions.
        # Strip those and retry once before giving up.
        cleaned = raw_text.replace("```json", "").replace("```", "").strip()
        return json.loads(cleaned)


def explain_flagged_flows(flows_with_reasons):
    """
    flows_with_reasons: list of (flow, reasons) tuples -- only the ones
    that already failed at least one rule.
    Returns a list of dicts combining the original flow with the AI's
    explanation.
    """
    client = Anthropic()
    results = []

    for flow, reasons in flows_with_reasons:
        explanation = explain_flow(flow, reasons, client=client)
        results.append({
            "flow": flow,
            "rule_reasons": reasons,
            "ai": explanation,
        })

    return results


if __name__ == "__main__":
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY before running this file directly.")
        raise SystemExit(1)

    test_flow = {
        "src_ip": "192.168.1.10", "dst_ip": "45.33.32.156", "dst_port": 31337,
        "protocol": "TCP", "packet_count": 1, "total_bytes": 54,
        "duration_seconds": 0.0, "syn_no_reply": True,
    }
    test_reasons = ["Unusual destination port: 31337", "SYN sent with no reply"]

    result = explain_flow(test_flow, test_reasons)
    print(json.dumps(result, indent=2))
