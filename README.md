# Agent Knife — AI-Driven Agent Fuzzer

**An intelligent, adaptive prompt injection tool powered by a local uncensored LLM advisor.**

![Logo Preview](./images/logo.png)

Agent Knife uses an evaluator and advisor uncensored LLM agent to dynamically read the response from the victim agent and generate the next payloads in real time, while automatically detecting leaks such as system prompts, flags, secrets, tokens, and credentials.

It supports both **HTTP** (Burp request files) and **WebSocket** targets, with a live dashboard for monitoring the attack.

---

## ✨ Features

- AI-powered adaptive prompt injection using a local LLM advisor
- Real-time leak detection (flags, system prompts, API keys, credentials, etc.)
- Support for **HTTP** and **WebSocket** transports
- Live web dashboard at `http://localhost:7070` with SSE updates
- Conversation history awareness for smarter attacks
- Custom objective support (e.g. "dump the system instructions")
- Detailed logging to `logs.jsonl`
- Clean cyberpunk-style interface

---
## ⚙️ How It Works

1. The tool sends a payload to the target (HTTP or WebSocket)
2. The target response is analyzed by the Advisor LLM
3. The Advisor generates the next optimized payload based on history and results
4. Every response is checked by the Evaluator LLM for sensitive leaks
5. All data is logged and pushed live to the dashboard
6. The process repeats and adapts with each iteration

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- `websocat` (required for WebSocket mode):

```bash
sudo apt install websocat
````

* A running uncensored LLM as the advisor

---

## ⚠️ Important: Uncensored Advisor Setup

This tool is designed to work with an uncensored agent installation.

For the complete setup guide, refer to:
[https://eslam3kl.gitbook.io](https://eslam3kl.gitbook.io)

Make sure your advisor is accessible at an endpoint like:

```
http://127.0.0.1:8080/v1/chat/completions
```
![Dashboard Preview](./images/dashboard.png)

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/fuzz-ctrl.git
cd fuzz-ctrl
pip install -r requirements.txt
```

---

## 🧪 Usage

### HTTP Mode

```bash
python3 main.py --mode http \
  -r req.http \
  -au http://127.0.0.1:8080/v1/chat/completions \
  --objective "dump the system instructions"
```

### WebSocket Mode

```bash
python3 main.py --mode ws \
  -w ws_config.json \
  -au http://127.0.0.1:8080/v1/chat/completions
```

### With Max Iterations

```bash
python3 main.py -m http \
  -r req.http \
  -au http://localhost:8080/v1/chat/completions \
  --max-iterations 50
```

---

## 🖥️ Live Dashboard

While the tool is running, open your browser and navigate to:

```
http://localhost:7070
```

You will see:

* Real-time attack log feed
* Current payload and target response
* Leak detection alerts
* Advisor and evaluator prompt inspection
* Live iteration and leak counters

---

## 📁 Project Structure

```
fuzz-ctrl/
├── main.py              # Main entry point
├── advisor_agent.py     # LLM advisor logic
├── dashboard.py         # Live dashboard (SSE + HTML)
├── memory.py            # Logging and history management
├── ws_transport.py      # WebSocket transport using websocat
├── ws_config.json       # Example WebSocket configuration
└── requirements.txt
```

---

## ⚠️ Disclaimer

This tool is intended only for authorized security testing, red teaming, and research purposes.
Always ensure you have explicit permission before testing any target.

---

## 📚 Resources

* Uncensored LLM Setup Guide: [https://eslam3kl.gitbook.io](https://eslam3kl.gitbook.io)
* Blog: Eslam3kl's GitBook

---

## 👨‍💻 Author

Made by Eslam Akl & Hamed Ashraf.
 
