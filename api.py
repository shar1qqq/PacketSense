"""
api.py

A small web API wrapping the existing pipeline (capture -> rules -> AI
explanations) so a React frontend can call it instead of using the CLI.

Endpoints:
    POST /api/analyze   -- upload a .pcap file, get back flows + AI explanations
    POST /api/chat       -- ask a question about a previously analyzed capture
    GET  /api/sample     -- analyze the bundled sample.pcap (quick demo, no upload)

Run locally:
    uvicorn api:app --reload --port 8000
"""

import os
import tempfile
import uuid

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from anthropic import Anthropic

from capture import run_tshark_conversations, parse_conversations
from rules import evaluate_flow
from ai_explainer import explain_flow

load_dotenv()

app = FastAPI(title="PacketSense API")

# Allows the React dev server (usually localhost:5173 or :3000) to call this API.
# For a portfolio project running locally this is fine left open; if you ever
# deploy this publicly, narrow allow_origins to your actual frontend's URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store of analyzed captures, keyed by an id we hand back to the
# frontend. Simple and fine for a local portfolio demo -- resets if the
# server restarts. A production version would use a real database instead.
CAPTURES = {}


class ChatRequest(BaseModel):
    capture_id: str
    message: str
    history: list = []  # list of {"role": "user"|"assistant", "content": str}


def parse_pcap(pcap_path):
    all_flows = []
    for protocol in ("tcp", "udp"):
        raw = run_tshark_conversations(pcap_path, protocol)
        all_flows.extend(parse_conversations(raw, protocol))
    return all_flows


def analyze_flows(all_flows):
    """Runs rules on every flow, and gets an AI explanation for flagged ones."""
    client = Anthropic()
    results = []

    for flow in all_flows:
        reasons = evaluate_flow(flow)
        entry = {
            "src_ip": flow["src_ip"],
            "dst_ip": flow["dst_ip"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "duration_seconds": flow["duration_seconds"],
            "flagged": bool(reasons),
            "rule_reasons": reasons,
            "ai": None,
        }

        if reasons:
            try:
                entry["ai"] = explain_flow(flow, reasons, client=client)
            except Exception as e:
                entry["ai"] = {
                    "threat_level": "unknown",
                    "explanation": f"AI explanation failed: {e}",
                    "recommended_action": "N/A",
                }

        results.append(entry)

    return results


def build_flow_context(analyzed_flows):
    lines = []
    for i, f in enumerate(analyzed_flows, start=1):
        flag_text = "; ".join(f["rule_reasons"]) if f["rule_reasons"] else "none"
        lines.append(
            f"{i}. {f['src_ip']} -> {f['dst_ip']}:{f['dst_port']} "
            f"({f['protocol']}) | packets={f['packet_count']} "
            f"bytes={f['total_bytes']} duration={f['duration_seconds']}s "
            f"| rule flags: {flag_text}"
        )
    return "\n".join(lines)


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith(".pcap"):
        raise HTTPException(status_code=400, detail="Please upload a .pcap file")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        all_flows = parse_pcap(tmp_path)
    finally:
        os.unlink(tmp_path)

    analyzed = analyze_flows(all_flows)

    capture_id = str(uuid.uuid4())
    CAPTURES[capture_id] = analyzed

    return {"capture_id": capture_id, "flows": analyzed}


@app.get("/api/sample")
async def analyze_sample():
    sample_path = os.path.join(os.path.dirname(__file__), "sample.pcap")
    all_flows = parse_pcap(sample_path)
    analyzed = analyze_flows(all_flows)

    capture_id = str(uuid.uuid4())
    CAPTURES[capture_id] = analyzed

    return {"capture_id": capture_id, "flows": analyzed}


@app.post("/api/chat")
async def chat(req: ChatRequest):
    if req.capture_id not in CAPTURES:
        raise HTTPException(status_code=404, detail="Unknown capture_id. Analyze a pcap first.")

    analyzed = CAPTURES[req.capture_id]
    flow_context = build_flow_context(analyzed)

    system_prompt = (
        "You are a network traffic assistant helping a beginner understand a "
        "packet capture. You have been given the full list of network flows "
        "from their capture below, including which ones a rule-based system "
        "flagged as suspicious and why.\n\n"
        "Answer their questions using ONLY this data. Explain things in plain, "
        "non-jargon English. If they ask about something not in the data, say "
        "so instead of guessing.\n\n"
        "Respond in plain text only, with no markdown formatting: no asterisks, "
        "no bullet symbols, no headers. Write in short paragraphs or simple "
        "numbered sentences instead, since your response is displayed as raw text.\n\n"
        f"CAPTURED FLOW DATA:\n{flow_context}"
    )

    client = Anthropic()
    messages = req.history + [{"role": "user", "content": req.message}]

    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        system=system_prompt,
        messages=messages,
    )

    reply_text = response.content[0].text
    return {"reply": reply_text}
