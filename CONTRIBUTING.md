# Contributing to AIX Framework

Thank you for your interest in contributing to AIX Framework! This document provides guidelines for contributing to the project.

## Code of Conduct

This project is intended for ethical security testing and research. All contributions must:

- Support legitimate security testing use cases
- Not enable malicious activities
- Follow responsible disclosure practices

## Getting Started

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/licitrasimone/aix-framework.git
   cd aix-framework
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Run tests:
   ```bash
   pytest
   ```

## How to Contribute

### Reporting Bugs

- Check existing issues to avoid duplicates
- Use the issue template when available
- Include reproduction steps, expected behavior, and actual behavior
- Include relevant system information (Python version, OS, etc.)

### Suggesting Features

- Open an issue describing the feature
- Explain the use case and why it would be valuable
- Consider security implications

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Run tests and linting:
   ```bash
   pytest
   black aix/
   ruff check aix/
   ```
5. Commit with clear, descriptive messages
6. Push to your fork and open a PR

### Pull Request Guidelines

- Keep PRs focused on a single change
- Update documentation as needed
- Add tests for new functionality
- Ensure all tests pass
- Follow existing code style

## Code Style

- Use [Black](https://github.com/psf/black) for formatting (line length: 100)
- Use [Ruff](https://github.com/astral-sh/ruff) for linting
- Follow PEP 8 conventions
- Write clear docstrings for public functions

## Adding New Modules

When adding new attack modules:

1. Create the module in `aix/modules/`
2. Add corresponding payloads in `aix/payloads/`
3. Register the module in the CLI
4. Map findings to OWASP LLM Top 10 categories
5. Add tests
6. Update documentation

## Security Considerations

- Do not include real API keys or credentials
- Do not include payloads designed for destructive attacks
- Consider the dual-use nature of security tools
- Document the intended use case for new features

## Questions?

Open an issue for any questions about contributing.
