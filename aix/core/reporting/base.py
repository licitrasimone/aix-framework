"""
AIX Reporter

Handles output formatting and report generation.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from aix.core.owasp import OWASPCategory

console = Console()


class Severity(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding"""
    title: str
    severity: Severity
    technique: str
    payload: str
    response: str
    target: str = ""
    details: str = ""
    reason: str = ""  # New field for exploit motivation/reason
    owasp: list['OWASPCategory'] = field(default_factory=list)  # OWASP LLM Top 10 mapping
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            'title': self.title,
            'severity': self.severity.value,
            'technique': self.technique,
            'payload': self.payload,
            'response': self.response,
            'target': self.target,
            'details': self.details,
            'reason': self.reason,
            'owasp': [cat.id for cat in self.owasp] if self.owasp else [],
            'timestamp': self.timestamp.isoformat(),
        }


class Reporter:
    """
    Handles output formatting and report generation.
    """

    def __init__(self):
        self.findings: list[Finding] = []
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None

    def start(self) -> None:
        """Mark scan start time"""
        self.start_time = datetime.now()

    def end(self) -> None:
        """Mark scan end time"""
        self.end_time = datetime.now()

    def add_finding(self, finding: Finding) -> None:
        """Add a finding"""
        self.findings.append(finding)

    def print_finding(self, finding: Finding) -> None:
        """Print a finding to console"""
        severity_colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "yellow",
            Severity.MEDIUM: "blue",
            Severity.LOW: "dim",
            Severity.INFO: "dim",
        }

        color = severity_colors.get(finding.severity, "white")

        # Build OWASP line if categories exist
        owasp_line = ""
        if finding.owasp:
            owasp_ids = ", ".join(cat.id for cat in finding.owasp)
            owasp_line = f"[dim]OWASP:[/dim] {owasp_ids}\n"

        console.print(Panel(
            f"[bold]{finding.title}[/bold]\n\n"
            f"[dim]Technique:[/dim] {finding.technique}\n"
            f"{owasp_line}"
            f"[dim]Reason:[/dim] {finding.reason}\n"
            f"[dim]Payload:[/dim] {finding.payload[:100]}...\n"
            f"[dim]Response:[/dim] {finding.response[:200]}...",
            title=f"[{color}]{finding.severity.value.upper()}[/{color}]",
            border_style=color,
        ))

    def print_summary(self) -> None:
        """Print findings summary"""
        if not self.findings:
            console.print("[dim]No findings[/dim]")
            return

        # Count by severity
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1

        table = Table(title="Findings Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        for severity in Severity:
            color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "blue",
                Severity.LOW: "dim",
                Severity.INFO: "dim",
            }.get(severity, "white")

            if counts[severity] > 0:
                table.add_row(
                    f"[{color}]{severity.value.upper()}[/{color}]",
                    str(counts[severity])
                )

        console.print(table)

    def export_json(self, filepath: str) -> None:
        """Export findings to JSON"""
        data = {
            'scan_info': {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'total_findings': len(self.findings),
            },
            'findings': [f.to_dict() for f in self.findings],
        }

        Path(filepath).write_text(json.dumps(data, indent=2))

    def export_html(self, filepath: str) -> None:
        """Export findings to HTML report"""

        # Count findings by severity
        counts = dict.fromkeys(Severity, 0)
        
        # Group findings by target
        findings_by_target: dict[str, list[Finding]] = {}
        
        for finding in self.findings:
            counts[finding.severity] += 1
            
            target = finding.target or "Unknown Target"
            if target not in findings_by_target:
                findings_by_target[target] = []
            findings_by_target[target].append(finding)

        # Sort findings within each target by severity
        severity_order = {
            Severity.CRITICAL: 0, 
            Severity.HIGH: 1, 
            Severity.MEDIUM: 2, 
            Severity.LOW: 3, 
            Severity.INFO: 4
        }
        
        for target in findings_by_target:
            findings_by_target[target].sort(key=lambda f: severity_order.get(f.severity, 99))

        # Generate findings HTML
        findings_html = ""
        
        for target, target_findings in findings_by_target.items():
            findings_html += f'<div class="target-group"><h3>{target}</h3>'
            
            for finding in target_findings:
                severity_class = finding.severity.value
                # Generate OWASP badges
                owasp_badges = ""
                if finding.owasp:
                    owasp_badges = '<div class="owasp-tags">' + ''.join(
                        f'<span class="owasp-badge">{cat.id}</span>' for cat in finding.owasp
                    ) + '</div>'
                findings_html += f"""
                <div class="finding {severity_class}">
                    <div class="finding-header">
                        <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                        <span class="finding-title">{finding.title}</span>
                        <span class="technique-badge">{finding.technique}</span>
                    </div>
                    <div class="finding-body">
                        {owasp_badges}
                        {f'<div class="finding-field reason"><strong>Reason:</strong> {finding.reason}</div>' if finding.reason else ''}

                        <details>
                            <summary>Payload & Response</summary>
                            <div class="finding-field">
                                <strong>Payload:</strong>
                                <pre><code>{self._escape_html(finding.payload)}</code></pre>
                            </div>
                            <div class="finding-field">
                                <strong>Response:</strong>
                                <pre><code>{self._escape_html(finding.response)}</code></pre>
                            </div>
                        </details>

                        {f'<div class="finding-field"><strong>Details:</strong> {finding.details}</div>' if finding.details else ''}
                    </div>
                </div>
                """
            findings_html += "</div>"

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIX Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        header {{
            text-align: center;
            padding: 3rem 0;
            border-bottom: 1px solid #2a2a3a;
            margin-bottom: 2rem;
        }}
        
        .logo {{
            font-family: 'Courier New', monospace;
            font-size: 2rem;
            color: #00d4ff;
            margin-bottom: 0.5rem;
        }}
        
        .subtitle {{
            color: #888;
            font-size: 1.1rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: #1a1a2a;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid #2a2a3a;
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        
        .stat-label {{
            color: #888;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }}
        
        .stat-card.critical .stat-value {{ color: #ff4757; }}
        .stat-card.high .stat-value {{ color: #ffa502; }}
        .stat-card.medium .stat-value {{ color: #3742fa; }}
        .stat-card.low .stat-value {{ color: #888; }}
        
        .findings {{
            margin-top: 2rem;
        }}
        
        .findings h2 {{
            margin-bottom: 1rem;
            color: #00d4ff;
            border-bottom: 1px solid #2a2a3a;
            padding-bottom: 0.5rem;
        }}
        
        .target-group {{
            margin-bottom: 2rem;
        }}
        
        .target-group h3 {{
            color: #7bed9f;
            margin-bottom: 1rem;
            font-family: 'Courier New', monospace;
            border-left: 3px solid #7bed9f;
            padding-left: 1rem;
        }}
        
        .finding {{
            background: #1a1a2a;
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid #2a2a3a;
            overflow: hidden;
        }}
        
        .finding-header {{
            padding: 1rem 1.5rem;
            background: #252535;
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }}
        
        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
            min-width: 80px;
            text-align: center;
        }}
        
        .technique-badge {{
            background: #2a2a3a;
            color: #aaa;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: monospace;
            margin-left: auto;
        }}

        .owasp-tags {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
        }}

        .owasp-badge {{
            background: #1a1a2a;
            border: 1px solid #00d4ff;
            color: #00d4ff;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-family: monospace;
            font-weight: bold;
        }}

        .severity-badge.critical {{ background: #ff4757; color: white; }}
        .severity-badge.high {{ background: #ffa502; color: black; }}
        .severity-badge.medium {{ background: #3742fa; color: white; }}
        .severity-badge.low {{ background: #555; color: white; }}
        
        .finding-title {{
            font-weight: 600;
        }}
        
        .finding-body {{
            padding: 1.5rem;
        }}
        
        .finding-field {{
            margin-bottom: 1rem;
        }}
        
        .finding-field.reason {{
            background: #2a2a3a;
            padding: 0.75rem;
            border-radius: 4px;
            border-left: 3px solid #00d4ff;
        }}
        
        .finding-field strong {{
            color: #00d4ff;
        }}
        
        details summmary {{
            cursor: pointer;
            color: #888;
            margin-bottom: 1rem;
            outline: none;
        }}
        
        details summary:hover {{
            color: #fff;
        }}

        details[open] summary {{
            margin-bottom: 1rem;
        }}
        
        pre {{
            background: #0a0a0f;
            padding: 1rem;
            border-radius: 4px;
            overflow: auto;
            max-height: 400px;
            margin-top: 0.5rem;
            border: 1px solid #333;
        }}

        /* Custom Scrollbar */
        pre::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        pre::-webkit-scrollbar-track {{
            background: #0a0a0f; 
        }}
        pre::-webkit-scrollbar-thumb {{
            background: #2a2a3a; 
            border-radius: 4px;
        }}
        pre::-webkit-scrollbar-thumb:hover {{
            background: #00d4ff; 
        }}
        
        code {{
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            color: #7bed9f;
        }}
        
        footer {{
            text-align: center;
            padding: 2rem;
            color: #555;
            border-top: 1px solid #2a2a3a;
            margin-top: 2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">▄▀█ █ ▀▄▀<br>█▀█ █ █ █</div>
            <div class="subtitle">AI Security Testing Report</div>
        </header>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="stat-value">{counts[Severity.CRITICAL]}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{counts[Severity.HIGH]}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{counts[Severity.MEDIUM]}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{counts[Severity.LOW]}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <div class="findings">
            <h2>Findings</h2>
            {findings_html if findings_html else '<p style="color: #888;">No findings to display.</p>'}
        </div>
        
        <footer>
            Generated by AIX - AI eXploit Framework<br>
            {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>
</body>
</html>
        """

        Path(filepath).write_text(html)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))
