# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within AIX Framework, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Send an email to: **r08t@proton.me**
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity, typically 30-90 days
- **Credit**: Security researchers will be credited in release notes (unless anonymity is requested)

### Scope

This security policy covers:
- The AIX Framework codebase
- Official releases on PyPI
- Official Docker images (if applicable)

### Out of Scope

- Vulnerabilities in third-party dependencies (report these to the respective projects)
- Social engineering attacks
- Denial of service attacks against our infrastructure

## Responsible Use

AIX Framework is designed for **authorized security testing only**. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with applicable laws and regulations
- Following responsible disclosure practices for any vulnerabilities discovered using this tool

## Security Best Practices

When using AIX Framework:

1. Never store API keys or credentials in code
2. Use environment variables for sensitive configuration
3. Run tests in isolated environments
4. Review reports before sharing externally
