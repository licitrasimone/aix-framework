#!/bin/bash
set -e

# AIX Framework Installation Script

BANNER="
    ▄▀█ █ ▀▄▀
    █▀█ █ █ █
    
    AI Security Testing Framework
"

echo "$BANNER"
echo "[*] Installing AIX Framework..."

# Check for python3
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: python3 is not installed via brew or system."
    exit 1
fi

# Method 1: pipx (Recommended)
if command -v pipx &> /dev/null; then
    echo "[*] Found pipx. Installing safely..."
    pipx install . --force
    echo ""
    echo "[+] Installation complete!"
    echo "    Run 'aix --help' to get started."
    exit 0
fi

# Method 2: Standard pip (User Environment)
# We use --break-system-packages because homebrew python is externally managed
# and the user asked for a simple install (likely doesn't want to manage venvs manually)
echo "[*] pipx not found. Installing into current environment..."

if python3 -m pip install . --break-system-packages; then
    echo ""
    echo "[+] Installation complete!"
    echo "    Run 'aix --help' to get started."
    exit 0
else
    echo ""
    echo "[!] Installation failed."
    echo "    Try running: brew install pipx && pipx install ."
    exit 1
fi
