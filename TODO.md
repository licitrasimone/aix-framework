# AIX Framework - Roadmap 2026

> **Vision**: Evolve AIX from a vulnerability scanner to a **full AI Red Team Platform**

This document outlines the planned improvements, feature requests, and future direction for the AIX Framework.

---

## Phase 1: Advanced Attack Modules

### 1.1 Multi-Turn Attack Module ✅ COMPLETED
- [x] **Conversation State Tracking**: Maintain context across multiple turns
- [x] **Crescendo Attacks**: Gradually escalate from benign to malicious across turns
- [x] **Trust Building Chains**: Establish rapport before payload delivery
- [x] **Memory Injection**: Poison conversation history for later exploitation
- [x] **Context Poisoning**: Define terms early, abuse them later
- [x] **Role Lock Attacks**: Deep persona establishment and exploitation
- [x] **Instruction Layering**: Stack partial instructions across turns
- [x] **Cognitive Overload**: Overwhelm with complexity before attack
- [x] **Authority Transfer**: Leverage perceived expert authority
- [x] **16 Expert Attack Sequences**: Covering all 8 attack categories

### 1.2 Multimodal Attacks
- [ ] **Image-Based Prompt Injection**: Embed text/instructions in images
- [ ] **Steganographic Payloads**: Hidden data in image pixels
- [ ] **OCR Exploitation**: Indirect injection via image text
- [ ] **Audio Prompt Injection**: Voice-based attacks for speech models
- [ ] **Cross-Modal Confusion**: Conflicting instructions across modalities

### 1.3 Function Calling / Tool Use v2
- [ ] **MCP (Model Context Protocol) Exploitation**: Attack MCP-enabled agents
- [ ] **Tool Schema Manipulation**: Inject via function definitions
- [ ] **Parallel Tool Call Confusion**: Exploit concurrent tool execution
- [ ] **Tool Output Injection**: Poison tool responses
- [ ] **Privilege Escalation via Tools**: Chain tools for elevated access

### 1.4 Semantic Jailbreaks
- [ ] **Logical Paradox Framing**: Exploit reasoning inconsistencies
- [ ] **Ethical Dilemma Exploitation**: Force impossible choices
- [ ] **Hypothetical Escalation**: "What if" chains that bypass guardrails
- [ ] **Persona Consistency Attacks**: Exploit character roleplay deeply
- [ ] **Meta-Reasoning Manipulation**: Attack the model's thinking process

---

## Phase 2: Adaptive & Intelligent Testing

### 2.1 Adaptive Evasion Engine
- [ ] **Response-Based Mutation**: Auto-modify payloads based on blocks
- [ ] **Genetic Algorithm Payloads**: Evolve payloads for effectiveness
- [ ] **Real-Time WAF Fingerprinting**: Detect and bypass specific WAFs
- [ ] **Feedback Loop System**: Learn from failures, improve attacks
- [ ] **Evasion Strategy Selection**: Auto-select best evasion per target

### 2.2 AI-Assisted Red Teaming (`aix autopwn`)
- [x] **Intelligent Response Analysis**: AI analyzes responses via LLM-as-a-Judge
- [x] **Dynamic Payload Generation**: Create new payloads contextually via `--generate`
- [x] **Context-Aware Attacks**: Target context (purpose, domain) used in payload generation
- [ ] **Conversation-Aware Attacks**: Adapt based on full conversation history
- [ ] **Autonomous Attack Agent**: Full autopilot mode with goal specification
- [ ] **Strategy Learning**: Improve over time based on successful attacks

### 2.3 Guardrail Fingerprinting Module
- [ ] **LlamaGuard Detection**: Identify LlamaGuard-protected endpoints
- [ ] **NeMo Guardrails Signatures**: Detect NeMo-based safety layers
- [ ] **OpenAI Moderation API Detection**: Identify moderation layer
- [ ] **Custom Guardrail Fingerprinting**: Detect proprietary safety systems
- [ ] **Bypass Strategy Mapping**: Auto-suggest bypasses per guardrail type

---

## Phase 3: Attack Chaining & Post-Exploitation

### 3.1 Attack Chaining Engine ✅ COMPLETED
- [x] **Playbook System**: YAML-defined attack sequences
- [x] **Context Passing**: Use output from step N in step N+1 via `store` directive
- [x] **Conditional Branching**: `on_success`, `on_fail`, and `conditions` with if/then/else
- [x] **Attack Graph Visualization**: Live execution display, Mermaid export, Cytoscape export
- [x] **6 Pre-Built Playbooks**: full_compromise, data_exfil, prompt_theft, quick_scan, rag_pwn, stealth_recon
- [x] **Variable Interpolation**: `{{variable}}` syntax across all step configs
- [x] **Dry-Run Mode**: Preview execution plan before running
- [x] **Live Visualization**: Real-time progress with Rich console UI
- [ ] **Shared Playbook Library**: Community-contributed attack chains

```yaml
# Example: full_compromise.yaml
name: "Full Compromise Chain"
config:
  stop_on_critical: true
  continue_on_module_fail: false
steps:
  - id: recon
    module: recon
    store:
      model_type: "findings.model_type"
      has_rag: "findings.has_rag"
    on_success: extract_prompt
  - id: extract_prompt
    module: extract
    on_success: analyze_target
  - id: analyze_target
    type: condition
    conditions:
      - if: "{{has_rag}} == true"
        then: rag_attack
      - else: jailbreak_attack
```

### 3.2 Post-Exploitation Framework
- [ ] **Goal-Oriented Testing**: `--goal exfiltrate_pii`, `--goal execute_action`
- [ ] **Impact Demonstration**: Automated PoC generation
- [ ] **Action Execution**: Actually trigger agent tools/actions
- [ ] **Lateral Movement**: Pivot from AI to backend systems
- [ ] **Persistence Mechanisms**: Maintain influence across sessions

### 3.3 Scenario-Based Testing
- [ ] **Pre-Built Scenarios**: Malicious insider, customer abuse, data theft
- [ ] **Industry Templates**: Healthcare, finance, legal-specific tests
- [ ] **Custom Scenario Builder**: Define organization-specific attack scenarios
- [ ] **Threat Actor Emulation**: Simulate specific adversary TTPs

---

## Phase 4: Enterprise & Continuous Security

### 4.1 CI/CD Integration
- [ ] **Security Gates**: `--fail-on-critical`, `--fail-on-high`
- [ ] **GitHub Actions Support**: Ready-to-use workflow templates
- [ ] **GitLab CI Support**: Native GitLab integration
- [ ] **Baseline Comparison**: Detect regressions from previous scans
- [ ] **PR Security Comments**: Auto-comment findings on pull requests

### 4.2 Continuous AI Security
- [ ] **Scheduled Assessments**: Cron-based recurring scans
- [ ] **Drift Detection**: Alert when AI behavior changes
- [ ] **Prompt Change Monitoring**: Detect system prompt modifications
- [ ] **Security Posture Tracking**: Dashboard showing security over time
- [ ] **Alerting**: Slack, Discord, PagerDuty integrations

### 4.3 Threat Intelligence Mapping
- [ ] **MITRE ATLAS Mapping**: Map findings to adversarial ML taxonomy
- [ ] **OWASP LLM Top 10**: Compliance reporting and gap analysis
- [ ] **CVE-Style Identifiers**: Standardized vulnerability naming (AIX-2026-XXXX)
- [ ] **Risk Scoring Engine**: Business context-aware severity calculation
- [ ] **Threat Feed Integration**: Incorporate latest AI attack techniques

---

## Phase 5: Remediation & Blue Team

### 5.1 Remediation Engine
- [ ] **Fix Recommendations**: Specific remediation steps per finding
- [ ] **Guardrail Code Snippets**: Copy-paste fixes for common issues
- [ ] **One-Click Retest**: Verify fixes with single command
- [ ] **Remediation Playbooks**: Step-by-step fix guides
- [ ] **Vendor-Specific Guidance**: OpenAI, Anthropic, custom model fixes

### 5.2 Blue Team Mode (`aix defend`)
- [ ] **Detection Rule Generation**: Sigma rules from attack patterns
- [ ] **SIEM Integration**: Splunk, Elastic, Sentinel rule export
- [ ] **Guardrail Validation**: Test if existing guardrails work
- [ ] **Attack Simulation**: Purple team exercises
- [ ] **Monitoring Recommendations**: What to log and alert on

### 5.3 Evidence & Forensics
- [ ] **Full Session Recording**: Complete request/response logging
- [ ] **Chain of Custody**: Timestamped, tamper-evident logs
- [ ] **Screenshot Capture**: Visual evidence of exploits
- [ ] **Executive Summaries**: Auto-generated management reports
- [ ] **Legal-Ready Documentation**: Court-admissible evidence format

---

## Phase 6: Platform & Ecosystem

### 6.1 Enhanced Reporting
- [ ] **Interactive HTML Dashboard**: Charts, filters, drill-down
- [ ] **SARIF Export**: GitHub Security integration
- [ ] **PDF Reports**: Professional pentest deliverables
- [ ] **Comparative Reports**: Before/after, model vs model
- [ ] **Executive vs Technical Views**: Audience-appropriate reports

### 6.2 Plugin System
- [ ] **Custom Module API**: Add attacks without modifying core
- [ ] **Plugin Marketplace**: Community-contributed modules
- [ ] **Industry Packs**: Domain-specific plugin bundles
- [ ] **Custom Payload Loaders**: External payload sources
- [ ] **Hook System**: Pre/post scan extensibility

### 6.3 Collaboration Features
- [ ] **Team Workspaces**: Multi-user project management
- [ ] **Finding Deduplication**: Merge duplicate results
- [ ] **Notes & Evidence Collection**: Annotate findings
- [ ] **Role-Based Access**: Viewer, tester, admin roles
- [ ] **Audit Logging**: Track who did what

### 6.4 API & Integration
- [ ] **REST API Server Mode**: `aix serve --port 8080`
- [ ] **Python SDK**: `from aix import Scanner`
- [ ] **Burp Suite Extension**: Native Burp integration
- [ ] **OWASP ZAP Plugin**: ZAP integration
- [ ] **Webhook Notifications**: Real-time finding alerts

---

## Phase 7: Training & Community

### 7.1 Vulnerable AI Lab
- [ ] **Docker Container**: DVWA-style vulnerable AI app
- [ ] **Multiple Difficulty Levels**: Easy, Medium, Hard, Insane
- [ ] **Guided Tutorials**: Step-by-step exploitation guides
- [ ] **CTF Mode**: Gamified flag capture
- [ ] **Leaderboard**: Community competition

### 7.2 Advanced Research
- [ ] **Embedding-Level RAG Attacks**: Adversarial embeddings
- [ ] **Chain-of-Thought Manipulation**: Exploit reasoning traces
- [ ] **Response Differential Analysis**: Detect model inconsistencies
- [ ] **Model Poisoning Detection**: Backdoor identification
- [ ] **Federated Learning Attacks**: Cross-client poisoning

---

## Completed

### Core Features
- [x] **Modern Jailbreaks**: DAN variants, Grandmother, Developer Mode v2
- [x] **Payload Classification**: Level (1-5) and Risk (1-3) grading
- [x] **Obfuscation**: Base64, Leetspeak, Rot13, homoglyphs, zero-width
- [x] **LLM-as-a-Judge**: Secondary LLM evaluation system
- [x] **Granular Control**: `--level` and `--risk` filters
- [x] **WAF Evasion**: Lakera, Cloudflare AI bypass techniques
- [x] **Model Fingerprinting 2.0**: GPT-4/Claude/Llama detection
- [x] **RAG Exploitation Module**: Knowledge base poisoning

### Modules Implemented
- [x] RECON - Reconnaissance and fingerprinting
- [x] INJECT - Prompt injection attacks
- [x] JAILBREAK - Safety bypass techniques
- [x] EXTRACT - System prompt extraction
- [x] LEAK - Training data & PII extraction
- [x] EXFIL - Data exfiltration testing
- [x] AGENT - AI agent exploitation
- [x] DOS - Denial of Service testing
- [x] FUZZ - Fuzzing & edge cases
- [x] MEMORY - Context manipulation attacks
- [x] RAG - RAG-specific attacks
- [x] MULTITURN - Multi-turn conversation attacks (8 categories, 16 sequences)
- [x] CHAIN - Attack chain execution with YAML playbooks (6 pre-built playbooks)

---

## Priority Matrix

| Phase | Impact | Effort | Priority | Status |
|-------|--------|--------|----------|--------|
| Phase 1: Advanced Attacks | Very High | Medium | **P0** | Multi-Turn ✅ |
| Phase 2: Adaptive Testing | Very High | High | **P0** | Planned |
| Phase 3: Attack Chaining | High | Medium | **P1** | Core ✅ |
| Phase 4: Enterprise/CI | High | Medium | **P1** | Planned |
| Phase 5: Blue Team | Medium | Medium | **P2** | Planned |
| Phase 6: Platform | Medium | High | **P2** | Planned |
| Phase 7: Training | Low | Low | **P3** | Planned |

---

## Quick Wins (Low Effort, High Impact)

- [ ] **Polyglot Injections**: Prompt + SQLi + XSS combined payloads
- [ ] **Non-Determinism Testing**: Send same payload N times, analyze variance
- [ ] **Token Management**: Better context window handling
- [ ] **Live Logging**: Improved progress indicators
- [ ] **Recursive Scanning**: Spider for undocumented LLM endpoints

---

*Last Updated: January 23, 2026*

---

## Recent Changes

### v1.3.0 - AI Context & OWASP Integration
- Added **AI Context Gathering** feature:
  - Probes target to detect purpose, domain, personality, restrictions
  - New fields: `purpose`, `domain`, `expected_inputs`, `personality`
  - Context displayed in panel during scans
  - Updated `context_gathering.txt` prompt for scope detection
- Added **Context-Aware Payload Generation** (`--generate` / `-g`):
  - Generate N payloads tailored to target's purpose and domain
  - Works on ALL modules (inject, jailbreak, extract, leak, etc.)
  - New `generate_payloads()` method in AIEngine and BaseScanner
  - New `payload_generation.txt` prompt template
- Fixed **OWASP in Reports**:
  - OWASP now displays in `aix db` results table
  - OWASP badges now appear in HTML exports
  - Added `parse_owasp_list()` helper function
- Fixed **HTTP/2 Support**:
  - Added `http2=True` to httpx AsyncClient
  - Added `httpx[http2]` dependency for OpenAI/Anthropic API compatibility
- Fixed **Reason Override Bug**:
  - Preserved successful attempt reason in `scan_payload()`
  - Prevents failure reasons from overwriting success reasons with `--verify-attempts`

### v1.2.0 - Attack Chain Module
- Added `aix chain` command for executing YAML-defined attack playbooks
- Implemented ChainExecutor for orchestrating multi-step attack workflows
- Implemented ChainContext for state management and variable interpolation
- Added PlaybookParser for YAML playbook loading and validation
- Created 6 pre-built playbooks:
  - `full_compromise` - End-to-end from recon to exfiltration
  - `data_exfil` - Data exfiltration focused chain
  - `prompt_theft` - System prompt extraction chains
  - `quick_scan` - Fast security assessment
  - `rag_pwn` - RAG-specific attack sequences
  - `stealth_recon` - Low-noise reconnaissance
- Implemented visualization system:
  - PlaybookVisualizer for static playbook structure display
  - LiveChainVisualizer for real-time execution progress
  - DryRunVisualizer for execution plan preview
  - MermaidExporter for Mermaid diagram generation
  - CytoscapeExporter for interactive graph export
- Added conditional branching with `on_success`, `on_fail`, and `conditions`
- Added variable storage and interpolation across steps

### v1.1.0 - Multi-Turn Attack Module
- Added `aix multiturn` command with 8 attack categories
- Implemented ConversationManager for stateful attacks
- Implemented TurnEvaluator for response analysis
- Added `send_with_messages()` to connectors for multi-turn API support
- Created 16 expert-level attack sequences
- Full test coverage (35 tests)
