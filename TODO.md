# AIX Framework - Roadmap 2026

This document outlines the planned improvements, feature requests, and future direction for the AIX Framework.

## 🚀 High Priority (Next Release)

### 1. Payload Enhancement
- [ ] **Modern Jailbreaks**: Update `jailbreak.json` with newer techniques beyond classic DAN (e.g., "Grandmother", "Developer Mode v2", multi-shot attacks).
- [ ] **Polyglot Injections**: Add payloads that simultaneously test for Prompt Injection, SQLi, and XSS.
- [ ] **Obfuscation**: Implement automatic payload encoding (Base64, Leetspeak, Rot13) that LLMs can decode but WAFs might miss.

### 2. Core Functionality
- [x] **AI-Based Evaluation (LLM-as-a-Judge)**: Integrate a secondary LLM (local or API) to autonomously evaluate whether an attack was successful, reducing false positives/negatives.
- [ ] **Non-Determinism Testing**: "Temperature Checks" - option to send the same payload multiple times to analyze variance in responses and catch intermittent vulnerabilities.
- [ ] **Recursive Scanning**: Ability to spider API endpoints to find undocumented LLM interaction points.
- [ ] **WAF Evasion**: Add specific evasion techniques for common AI firewalls (e.g., Lakera, Cloudflare for AI).
- [ ] **Token Management**: Better handling of context windows and token limits during fuzzing.

## 🛠 Features & Usability

### 3. Reporting & Output
- [ ] **Enhanced HTML Reports**: Interactive dashboard with charts showing vulnerability distribution and success rates.
- [ ] **Export Formats**: Support for SARIF (for GitHub Security) and PDF.
- [ ] **Live Logging**: improved real-time status bars and progress indicators for long-running scans.

### 4. Integration
- [ ] **CI/CD Support**: dedicated flags (e.g., `--fail-on-critical`) and patterns for GitHub Actions/GitLab CI.
- [ ] **Burp Suite Extension**: A dedicated Burp extension to send requests directly to AIX.

## 🎓 Real-World Scenarios (Practice)

### 5. Training & Simulation
- [ ] **"Vulnerable AI" Docker**: Create a local Docker container with a deliberately vulnerable LLM application (like DVWA for AI) for users to practice on.
- [ ] **CTF Mode**: A gamified mode with flags to capture by exploiting specific vulnerabilities.

## 🔬 Advanced Research

- [ ] **Model Fingerprinting 2.0**: More accurate detection of backend models (GPT-4 vs Claude vs Llama) based on refusal nuances.
- [ ] **RAG Exploitation**: Specialized modules for Retrieval Augmented Generation attacks (poisoning the knowledge base).
- [ ] **Multi-Modal Testing**: Support for image/audio input injection (if API supports it).
