"""
AIX - AI eXploit Framework

The first comprehensive AI/LLM security testing tool.
Like NetExec, but for AI.

Usage:
    aix recon https://company.com/chatbot
    aix inject https://api.openai.com/v1/chat -k sk-xxx
    aix jailbreak https://chat.company.com
"""

__version__ = "1.0.0"
__author__ = "AIX Team"
__license__ = "MIT"

from aix.core.connector import APIConnector, Connector, WebSocketConnector
from aix.core.reporting.base import Reporter
from aix.core.scanner import AIXScanner
from aix.db.database import AIXDatabase

__all__ = [
    'AIXScanner',
    'Connector',
    'APIConnector',
    'WebSocketConnector',
    'Reporter',
    'AIXDatabase',
]
