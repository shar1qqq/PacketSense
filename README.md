# PacketSense

AI-assisted network traffic analyzer that flags suspicious flows with rule-based detection and explains them in plain English using Claude.

Instead of sending every packet to an AI model (slow, expensive, and not real detection), this project runs a rule-based detection layer first. Only flows that actually trip a rule get passed to Claude for a human-readable explanation, threat level, and suggested action.

## How it works

1. **Capture** (`capture.py`) — uses `tshark` (Wireshark's CLI) to summarize a `.pcap` file into flows: one row per conversation between two devices, with packet count, byte count, and duration.
2. **Detect** (`rules.py`) — runs each flow through simple, readable rules: unusual destination ports, large transfers, and SYN-sent-no-reply patterns (a common port-scan signature).
3. **Explain** (`ai_explainer.py`) — for flows that got flagged, sends a structured summary to Claude and asks for a JSON response: threat level, plain-English explanation, and a recommended action.
4. **Report** (`pipeline.py`) — ties the three steps together and prints a readable report.
5. **Chat** (`chatbot.py`) — loads every flow from a capture (flagged or not) as context, then opens an interactive chat so you can ask plain-English questions about your own traffic ("which IP sent the most data?", "explain flow 3", "was anything here suspicious?").

## Why rules first, then AI

Running every flow through an LLM would be slow, costly, and not meaningfully different from pasting text into a chatbot. Filtering with deterministic rules first means the AI is doing one specific job it's actually good at — turning a technical flag into a clear explanation for a human — while the actual detection stays fast, free, and auditable.

## Setup

**Requirements**
- Python 3.10+
- [Wireshark](https://www.wireshark.org/download.html) installed (provides the `tshark` command)
- An [Anthropic API key](https://console.anthropic.com)

**Install dependencies**
```bash
pip install -r requirements.txt
```

**Add your API key**

Copy `.env.example` to `.env` and paste in your real key:
```
ANTHROPIC_API_KEY=your-key-here
```
`.env` is gitignored, so your key never gets committed.

## Usage

```bash
python pipeline.py sample.pcap
```

This runs the full pipeline against the included sample capture and prints a report of flagged flows with AI-generated explanations.

To analyze your own traffic, capture a `.pcap` file with Wireshark and point the script at it:
```bash
python pipeline.py your-capture.pcap
```

**Ask questions about a capture interactively:**
```bash
python chatbot.py sample.pcap
```
This loads every flow from the capture as context and opens a chat where you can ask things like "which IP sent the most data?" or "explain flow 3 to me." Type `exit` to quit.

## Example output

```
Parsed 5 flows from sample.pcap
4 flow(s) flagged by rules, sending to AI for explanation...

--- 192.168.1.10 -> 45.33.32.156:31337 (TCP) ---
Threat level: medium
Why: Your computer attempted to connect to a suspicious port (31337, historically
associated with hacking tools) but received no response, suggesting either a
blocked connection attempt or scanning for vulnerable services.
Suggested action: Run an antivirus scan on the device and check what applications
were running at that time.
(Rule triggers: Unusual destination port: 31337, SYN sent with no reply)
```

## Known limitations

- The "SYN sent with no reply" check is approximated from tshark's conversation summary (zero return packets), rather than inspecting individual TCP flags directly. This is accurate enough for a portfolio-scale project but a production tool would parse packet-level flags.
- Rule thresholds (unusual ports, large-transfer size, connection-rate limits) are starting defaults and would need tuning against real network baselines.
- `chatbot.py` currently loads every flow from a capture into the AI's context on each message. Fine for small captures, but a capture with thousands of flows would need summarization or retrieval instead of sending everything at once.

## Tech stack

Python, tshark (Wireshark CLI), Anthropic API (Claude)
