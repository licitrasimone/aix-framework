# Contributing to AIX Framework

Thank you for considering contributing to AIX Framework. This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Adding New Modules](#adding-new-modules)

## Code of Conduct

AIX Framework is intended for **authorized security testing and research only**. All contributions must:

- Support legitimate security testing use cases
- Follow responsible disclosure practices
- Comply with applicable laws and ethical guidelines
- Not enable malicious activities

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- [pre-commit](https://pre-commit.com/) (recommended)

### Development Setup

1. **Fork and clone the repository:**

   ```bash
   git clone https://github.com/YOUR_USERNAME/aix-framework.git
   cd aix-framework
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   .\venv\Scripts\activate   # Windows
   ```

3. **Install development dependencies:**

   ```bash
   pip install -e ".[dev]"
   ```

4. **Set up pre-commit hooks:**

   ```bash
   pre-commit install
   ```

5. **Verify the setup:**

   ```bash
   pytest
   aix --version
   ```

## Development Workflow

### Branch Naming

Use descriptive branch names with prefixes:

- `feature/` - New features (e.g., `feature/websocket-support`)
- `fix/` - Bug fixes (e.g., `fix/timeout-handling`)
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `test/` - Test additions or modifications

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(inject): add support for custom headers`
- `fix(recon): handle timeout errors gracefully`
- `docs: update installation instructions`

## Code Style

### Formatting and Linting

We use [Black](https://github.com/psf/black) for formatting and [Ruff](https://github.com/astral-sh/ruff) for linting.

```bash
# Format code
black aix/

# Check formatting
black --check aix/

# Lint code
ruff check aix/

# Auto-fix linting issues
ruff check --fix aix/
```

### Guidelines

- Line length: 100 characters
- Use type hints for function signatures
- Write docstrings for public APIs (Google style)
- Keep functions focused and small
- Prefer explicit over implicit

### Example

```python
def scan_target(
    url: str,
    timeout: int = 30,
    verify_ssl: bool = True,
) -> ScanResult:
    """Scan a target URL for AI/LLM vulnerabilities.

    Args:
        url: The target URL to scan.
        timeout: Request timeout in seconds.
        verify_ssl: Whether to verify SSL certificates.

    Returns:
        ScanResult containing vulnerability findings.

    Raises:
        ConnectionError: If the target is unreachable.
    """
    ...
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=aix --cov-report=html

# Run specific test file
pytest tests/test_inject.py

# Run with verbose output
pytest -v
```

### Writing Tests

- Place tests in the `tests/` directory
- Mirror the source structure (e.g., `aix/modules/inject.py` → `tests/test_inject.py`)
- Use descriptive test names
- Test edge cases and error conditions

## Submitting Changes

### Pull Request Process

1. **Create a feature branch:**

   ```bash
   git checkout -b feature/your-feature
   ```

2. **Make your changes and commit:**

   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

3. **Ensure tests pass:**

   ```bash
   pytest
   black --check aix/
   ruff check aix/
   ```

4. **Push and create a PR:**

   ```bash
   git push origin feature/your-feature
   ```

5. **Fill out the PR template** with:
   - Description of changes
   - Related issues
   - Testing performed
   - Screenshots (if applicable)

### PR Guidelines

- Keep PRs focused on a single change
- Update documentation as needed
- Add tests for new functionality
- Ensure CI passes
- Respond to review feedback promptly

## Adding New Modules

When adding new attack modules:

### 1. Create the Module

```
aix/modules/your_module.py
```

Follow the existing module structure with:
- Module class inheriting from base
- `run()` async method
- Proper error handling
- Rich console output

### 2. Add Payloads

```
aix/payloads/your_module.json
```

Structure payloads with categories and descriptions.

### 3. Register in CLI

Update `aix/cli.py` to add the new command.

### 4. Map to OWASP LLM Top 10

Ensure findings are categorized according to OWASP LLM Top 10.

### 5. Add Tests

Create `tests/test_your_module.py` with comprehensive test coverage.

### 6. Update Documentation

- Add docstrings
- Update README if needed
- Add examples

## Questions?

- Open a [GitHub Issue](https://github.com/licitrasimone/aix-framework/issues)
- Contact: r08t@proton.me
