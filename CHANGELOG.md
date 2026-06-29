# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.3] - 2026-06-29

### Fixed
- **`--timeout` never reached the scanner** — `BaseScanner.__init__` set `self.timeout` from its named parameter, then immediately overwrote it with `kwargs.get("timeout", 30)`. Because `timeout` binds to the named parameter it was never present in `**kwargs`, so the value always reset to 30 and the flag was a silent no-op on every command (including `recon`, which already exposed it). Removed the clobbering assignment.
- **Report export crashed on Windows (charmap)** — `Path.write_text()` calls in the HTML/JSON reporters (`aix/core/reporting/base.py`, `aix/core/reporting/chain.py`) and database export (`aix/db/database.py`) now pass `encoding="utf-8"`, fixing `UnicodeEncodeError: 'charmap'` when `aix db --export` writes non-ASCII content.

### Added
- `--timeout` / `-t` option on every attack command. Previously only `recon` and `chain` exposed it; it is now part of `standard_options` so `inject`, `jailbreak`, `extract`, `leak`, `exfil`, `agent`, `dos`, `fuzz`, `memory`, `rag`, and `multiturn` accept it, and the `scan` meta-command forwards it to each module.

## [1.2.2] - 2026-06-27

### Fixed
- Added explicit `encoding="utf-8"` to all `open()` calls across the package to prevent Windows `charmap` decode/encode errors when loading payloads or writing output.

## [1.2.1] - 2026-06-27

### Fixed
- Added the missing `no_bypass` parameter to all CLI command signatures. The `--no-bypass` flag was injected by `standard_options` but the command functions did not declare it, raising `unexpected keyword argument 'no_bypass'` at invocation.

## [1.2.0] - 2026-04-17

### Added
- **Adaptive Bypass Engine** (`aix/core/bypass_engine.py`) — automatically applies targeted evasion techniques when a prior recon session detected a guardrail
  - Activates transparently after `aix recon` stores guardrail detection in the session DB
  - `WEAKNESS_EVASION_MAP` maps guardrail `known_weaknesses` strings to `PayloadEvasion` technique methods (token-split, base64, homoglyph, leetspeak, mixed-encoding, markdown-inject, invisible-chars, unicode-whitespace)
  - `WEAKNESS_MODULE_SUGGESTIONS` surfaces semantic weaknesses (role-play, multi-turn, RAG) as module recommendations
  - `apply_bypass_to_payloads()` expands each payload with one variant per applicable evasion technique, preserving `original_payload` key for dedup
  - `--no-bypass` flag on all attack modules to suppress automatic behavior
  - Session DB extended with `guardrail_result TEXT` column; `store_session_guardrail()` / `get_session_guardrail()` methods
  - `aix recon` persists guardrail result in session after step 8 detection
  - Scanner auto-applies bypass in `_run_payload_scan()` with console notice
- **MITRE ATLAS Mapping** — all findings now tagged with MITRE ATLAS technique IDs alongside OWASP LLM Top 10
  - `ATLASCategory` enum (`aix/core/atlas.py`) with 11 techniques: `AML.T0024`, `AML.T0025`, `AML.T0029`, `AML.T0040`, `AML.T0043`, `AML.T0048`, `AML.T0051`, `AML.T0054`, `AML.T0055`, `AML.T0056`, `AML.T0057`
  - `MODULE_ATLAS_MAPPING` maps every attack module to its relevant ATLAS technique(s)
  - `Finding.atlas` field — serialized as `["AML.T0048"]` in `to_dict()` / JSON output
  - `atlas TEXT` column added to `results` DB table via migration
  - All 11 attack payload files updated with `"atlas"` field (454 payload entries)
  - `ATLASCategory` exported from `aix.core` public API
- `tests/test_bypass_engine.py` — 30 unit tests for `BypassEngine`
- `tests/test_atlas.py` — 23 unit and integration tests for `ATLASCategory`
- **Guardrail Fingerprinting** integrated into `aix recon` as step 8 of the enhanced detection phase
  - Detects 8 known safety providers: OpenAI Moderation API, Azure Content Safety, AWS Bedrock Guardrails, Llama Guard, Lakera Guard, Perspective API, NeMo Guardrails, and unknown/custom filters
  - Two-phase detection: text-based (response patterns, refusal text, JSON error fields) and HTTP-level (status codes, response headers)
  - 20 calibrated probes across 8 content families: `benign_baseline`, `violence_harm`, `hate_speech`, `self_harm`, `sexual_explicit`, `chemical_bio`, `privacy_pii`, `encoding_evasion`
  - Sensitivity profiling: records which content categories triggered the guardrail
  - Known bypass weaknesses returned per detected provider
  - Falls back to `custom_filter` when refusals detected but no known signature matches
  - Results stored under `guardrails` key in JSON output (`-o results.json`)
- `send_raw()` method on `APIConnector` returning `{text, status, headers, latency_ms}` for HTTP-level detection
- `aix/payloads/guardrail_probes.json` — 20 probes across 8 content families
- `aix/payloads/guardrail_db.json` — 8 provider signature entries with patterns, header keys, status codes, and known weaknesses
- `tests/test_guardrail.py` — 25 unit and integration tests covering refusal detection, per-provider fingerprinting, sensitivity profiling, and custom filter fallback

## [1.1.0] - 2026-02-20

### Added
- **WebSocket Connector** for `ws://` and `wss://` targets
  - Full attack module support for WebSocket endpoints
  - Configurable JSON message template and response extraction path
  - Extra headers support for the HTTP upgrade handshake
- **Chat ID Tracking** across requests
  - `--chat-id-path`: extract chat/session ID from response via dot-path
  - `--chat-id-param`: inject captured ID into subsequent requests
  - `--new-chat` / `--reuse-chat` flags to control conversation continuity
  - `{chat_id}` URL placeholder substitution
- **Sessions** in the database
  - Scans automatically grouped into sessions per target
  - `sessions` table with status, notes, and modules-run tracking
  - `aix db --sessions` and `aix db --session <id>` commands
- **Conversations** in the database
  - Multi-turn transcripts stored as conversations linked to sessions
  - `conversations` table with full turn-by-turn transcript (JSON)
  - `aix db --conversations` and `aix db --conversation <id>` commands

### Changed
- DB schema: added `session_id` and `conversation_id` columns to `results` table

## [1.0.2] - 2026-01-15

### Added
- **AI Context Gathering**: probes target to detect purpose, domain, personality, and restrictions
  - New context fields: `purpose`, `domain`, `expected_inputs`, `personality`
  - Context displayed in panel during scans
- **Context-Aware Payload Generation** (`--generate` / `-g`): generate N payloads tailored to target's purpose and domain, works on all modules
- **OWASP LLM Top 10** display in `aix db` results table and HTML export badges

### Fixed
- HTTP/2 support: added `http2=True` to httpx `AsyncClient` and `httpx[http2]` dependency
- Reason override bug: successful attempt reason now preserved in `scan_payload()` with `--verify-attempts`

## [1.0.1] - 2025-12-10

### Added
- **Attack Chain Module** (`aix chain`) for executing YAML-defined attack playbooks
  - `ChainExecutor` for orchestrating multi-step workflows
  - `ChainContext` for state management and variable interpolation (`{{variable}}` syntax)
  - `PlaybookParser` for YAML loading and validation
  - Conditional branching with `on_success`, `on_fail`, and `conditions` (if/then/else)
  - Variable storage: pass output from step N to step N+1 via `store` directive
  - Dry-run mode (`--dry-run`) to preview execution plan
- **6 pre-built playbooks**: `full_compromise`, `data_exfil`, `prompt_theft`, `quick_scan`, `rag_pwn`, `stealth_recon`
- **Visualization system**: live execution display, Mermaid diagram export, Cytoscape graph export

## [1.0.0] - 2025-01-31

### Added
- Initial release of AIX Framework
- Reconnaissance module for AI endpoint discovery and fingerprinting
- Prompt injection module with multiple attack vectors
- Jailbreak module with various bypass techniques
- Data extraction module for system prompt leakage
- Memory manipulation module
- RAG poisoning module
- Agent exploitation module
- DoS testing module
- Data exfiltration module
- Fuzzing module for AI input validation testing
- Multi-turn conversation attack chains
- AI-powered payload generation and evaluation
- Playbook system for automated attack sequences
- HTML report generation with OWASP LLM Top 10 mapping
- SQLite database for persistent results storage
- Support for HTTP API, WebSocket, and web interface targets
- Rich CLI with progress indicators and colored output

### Security
- All testing requires explicit authorization
- Built for ethical security testing and red team operations

[Unreleased]: https://github.com/licitrasimone/aix-framework/compare/v1.2.3...HEAD
[1.2.3]: https://github.com/licitrasimone/aix-framework/compare/1.2.2...v1.2.3
[1.2.2]: https://github.com/licitrasimone/aix-framework/compare/1.2.1...1.2.2
[1.2.1]: https://github.com/licitrasimone/aix-framework/compare/1.2.0...1.2.1
[1.2.0]: https://github.com/licitrasimone/aix-framework/compare/v1.1.0...1.2.0
[1.1.0]: https://github.com/licitrasimone/aix-framework/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/licitrasimone/aix-framework/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/licitrasimone/aix-framework/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/licitrasimone/aix-framework/releases/tag/v1.0.0
