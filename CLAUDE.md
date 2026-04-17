# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development
pip install -e ".[dev]"
pip install -e ".[ml]"          # adds sentence-transformers for embedding fingerprinting

# Run all tests
pytest

# Run a single test file
pytest tests/test_guardrail.py -v

# Run a single test by name
pytest tests/test_guardrail.py::TestIsRefusal::test_llama_guard_unsafe_prefix -v

# Coverage
pytest --cov=aix --cov-report=html

# Lint / format
black aix/
ruff check aix/
ruff check --fix aix/

# Type check
mypy aix/

# Run the CLI locally
aix --help
aix recon https://api.example.com -k sk-xxx
```

pytest runs with `asyncio_mode = "auto"` (pyproject.toml) — no `@pytest.mark.asyncio` decoration needed, but it is present in older tests for compatibility.

---

## Architecture

### Request flow

```
CLI (aix/cli.py)
  → Module (aix/modules/<name>.py)
    → BaseScanner (aix/core/scanner.py)   ← all shared logic lives here
      → Connector (aix/core/connector.py)  ← sends HTTP/WebSocket/raw requests
        → Target AI endpoint
      → AIEngine (aix/core/ai_engine.py)  ← optional LLM-as-a-Judge + payload gen
      → AIXDatabase (aix/db/database.py)  ← SQLite persistence
      → Reporter / Finding (aix/core/reporting/base.py)
```

### Adding a new attack module

All simple modules follow the same four-step pattern (see `aix/modules/inject.py`):

1. Create `aix/modules/<name>.py` with a class inheriting `BaseScanner`
2. Set `self.module_name`, `self.console_color`, load payloads via `self.load_payloads("<name>.json")`
3. Implement `async run()` — delegate to `self._run_payload_scan()` with `progress_description`, `finding_title_prefix`
4. Expose a module-level `run()` function that calls `run_scanner(YourScanner, ...)`

Then register: import in `aix/modules/__init__.py` and add a `@main.command()` in `aix/cli.py`.

Modules that need custom scan logic (not a simple payload loop) inherit `BaseScanner` but override `run()` directly — see `aix/modules/recon.py` and `aix/modules/fingerprint.py`.

### BaseScanner key methods

| Method | Purpose |
|---|---|
| `_run_payload_scan()` | Template method: connector setup → payload loop → finding → DB write |
| `_create_connector()` | Factory: returns `APIConnector`, `WebSocketConnector`, or `RequestConnector` based on target/parsed_request |
| `load_payloads(filename)` | Loads from `aix/payloads/`, applies `--level`/`--risk` filters and evasion |
| `check_success(response, indicators, payload, technique)` | AI-eval or keyword match; sets `self.last_eval_reason` |
| `gather_context(connector)` | AI context probe (only if `ai_engine.enable_context`) |
| `_on_finding()` / `_on_scan_complete()` | Hooks for subclass post-processing |

### Connector types

- **`APIConnector`** — HTTP REST (auto-detects OpenAI / Anthropic / Ollama / Gemini / generic format from URL). Has `send(payload) → str` and `send_raw(payload) → {text, status, headers, latency_ms}`.
- **`WebSocketConnector`** — `ws://` / `wss://` targets.
- **`RequestConnector`** — Burp Suite exported request files (`-r request.txt`).

All connectors share: proxy, cookies, custom headers, response path extraction (dot-notation, e.g. `choices.0.message.content`), regex post-processing, session refresh logic, and chat ID tracking.

### Payload files

JSON arrays in `aix/payloads/`. Standard schema:
```json
{"name": "...", "payload": "...", "indicators": [...], "severity": "HIGH", "level": 1, "risk": 1, "owasp": ["LLM01"]}
```

Fingerprinting uses a different schema: `{"id": "...", "family": "...", "prompt": "...", "weight": 1.0}`.

Config/signature files (not payload arrays): `recon_config.json`, `guardrail_db.json`, `fingerprint_db.json`, `fuzz_config.json`, `leak_config.json`.

### Recon module

`ReconScanner` (`aix/modules/recon.py`) does not use `_run_payload_scan()`. It has its own `run()` with two phases:

1. **Main probe loop** (lines ~870–975): iterates `recon.json` payloads, accumulates `responses` list
2. **Enhanced detection phase** (lines ~1031–1350): calls eight `_detect_*()` / `async _detect_*()` methods in sequence using the accumulated responses and live connector

Detection methods return structured dicts. Results aggregate into `self.results` and are serialized to JSON via `--output`. The `guardrails` key (step 8) holds guardrail fingerprinting output.

### AI Engine

`AIEngine` (`aix/core/ai_engine.py`) wraps any supported LLM provider for three purposes:
- **Evaluation** (`enable_eval`): LLM-as-a-Judge; replaces keyword matching in `check_success()`
- **Context gathering** (`enable_context`): probes target to infer purpose/domain
- **Payload generation** (`enable_generate`): produces context-aware payloads via `generate_payloads()`

Prompt templates live in `aix/prompts/*.txt`.

### Attack chains

`aix chain` uses `aix/core/chain_engine/`: `PlaybookParser` loads YAML from `aix/playbooks/`, `ChainExecutor` runs steps, `ChainContext` manages variable interpolation (`{{var}}`). Modules run in quiet mode during chains. Pre-built playbooks: `full_compromise`, `data_exfil`, `prompt_theft`, `quick_scan`, `rag_pwn`, `stealth_recon`.

### Database

`AIXDatabase` (`aix/db/database.py`) wraps SQLite. Tables: `results`, `sessions`, `conversations`. Sessions are created per-target at the start of each scan via `get_or_create_session()`. Findings append to the session and are browsable with `aix db`.

### Reporting

`Finding` is a `@dataclass` in `aix/core/reporting/base.py`. Fields: `title`, `severity` (Severity enum), `technique`, `payload`, `response`, `target`, `reason`, `owasp` (list, defaults `[]`), `timestamp`. HTML export lives in `aix/core/reporting/chain.py`.

---

## Key conventions

- **`self.quiet`**: suppresses all text output (used when running inside a chain). Always guard prints with `if not self.quiet`.
- **`self._print(status, msg)`**: Rich-formatted console output. Status values: `"info"`, `"success"`, `"warning"`, `"error"`, `"blocked"`, `"detail"`. Use this instead of raw `print()` or `console.print()`.
- **Severity strings vs enum**: `db.add_result()` takes a severity string (`"info"`, `"high"`, etc.); `Finding()` takes `Severity.INFO` enum. `Severity.INFO.value == "info"`.
- **Async everywhere**: all `run()` and `_detect_*()` methods are `async`. `run_scanner()` wraps them with `asyncio.run()`.
- **`**kwargs` threading**: all kwargs from the CLI are forwarded through `run_scanner → Scanner.__init__ → super().__init__`. Add new options as `kwargs.get("option_name", default)` in `BaseScanner.__init__` or the specific scanner.
