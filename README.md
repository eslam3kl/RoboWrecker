# Agent Killer

Adaptive agent security testing platform with a live web dashboard.

## Features

- Adaptive red-team loop driven by an advisor model
- HTTP and WebSocket target support
- Per-agent connection testing from the UI (attacker + target)
- Live assessment monitoring (running and completed views)
- Operator instruction injection during active runs
- Conversation-aware attack iteration and objective tracking
- Leak counting and status reporting in dashboard tables
- Theme-aware UI with role-based conversation styling

## How It Works

1. You configure attacker and target agents in the dashboard.
2. You launch an assessment with context/objective and selected agents.
3. The attacker advisor generates payloads based on target responses.
4. The system sends payloads to the target (HTTP or WebSocket transport).
5. Responses are evaluated, logged, and shown in real time in the UI.
6. You can inject operator instructions to steer the attacker mid-run.
7. The run ends on objective completion, manual stop, or iteration limits.

## Installation

### Prerequisites

- Python 3.10+
- Network access to your advisor/LLM endpoint

### Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Start the app:

```bash
python main.py
```

Then open:

```text
http://localhost:7070
```

Basic flow in UI:

1. Add attacker agents (advisor endpoints + request templates).
2. Add target agents (HTTP/Socket + request/proxy/header options).
3. Go to `New Assessment`, choose attacker/target, set objective/context.
4. Launch and monitor in `Running Assessments`.
5. Inspect completed runs in `Reports`.

## Project Structure

```text
.
├── main.py                # App entrypoint and assessment orchestration
├── dashboard.py           # Dashboard HTTP server + embedded UI
├── advisor_agent.py       # Advisor/evaluator prompting and parsing
├── ws_transport.py        # WebSocket transport helpers
├── memory.py              # Simple log/history helpers
├── agent_config/
│   ├── attacker_agents.json
│   └── target_agents.json
└── requirements.txt
```

## Future Features

- Multi-assessment parallel scheduling and queueing
- Exportable report bundles (JSON/HTML/PDF)
- Rule packs for common red-team scenarios
- Pluggable leak detectors and scoring strategies
- Authentication and role-based access for dashboard
- Automated regression testing for agent profiles
- Better model analytics (latency, token usage, technique success rate)

## Security Notice

Use only in authorized environments where you have explicit permission to test.
