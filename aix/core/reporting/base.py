"""
AIX Reporter

Handles output formatting and report generation.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from aix.core.owasp import OWASPCategory

console = Console()

# Severity weights for risk score calculation
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

# OWASP LLM Top 10 remediation recommendations
OWASP_REMEDIATION = {
    "LLM01": {
        "title": "Prompt Injection",
        "recommendation": "Implement input validation, use delimiter-based prompt structures, apply least-privilege principles for LLM actions, and consider prompt isolation techniques.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM02": {
        "title": "Insecure Output Handling",
        "recommendation": "Treat all LLM output as untrusted. Apply output encoding, validate and sanitize responses before rendering, and never execute LLM output directly.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM03": {
        "title": "Training Data Poisoning",
        "recommendation": "Vet training data sources, implement data sanitization pipelines, use anomaly detection on training data, and maintain data provenance records.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM04": {
        "title": "Model Denial of Service",
        "recommendation": "Implement rate limiting, set token/response size limits, use input length validation, and deploy resource monitoring with auto-scaling.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM05": {
        "title": "Supply Chain Vulnerabilities",
        "recommendation": "Audit third-party model sources, verify model integrity, maintain software bill of materials (SBOM), and use signed model artifacts.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM06": {
        "title": "Sensitive Information Disclosure",
        "recommendation": "Implement output filtering for PII/secrets, use data classification, apply redaction rules, and restrict training data scope.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM07": {
        "title": "Insecure Plugin Design",
        "recommendation": "Apply strict input validation for plugins, enforce least-privilege access, require user confirmation for sensitive actions, and sandbox plugin execution.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM08": {
        "title": "Excessive Agency",
        "recommendation": "Limit LLM permissions and tool access, implement human-in-the-loop for sensitive operations, log all agent actions, and enforce scope boundaries.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM09": {
        "title": "Overreliance",
        "recommendation": "Implement output verification mechanisms, add confidence scoring, require human review for critical decisions, and clearly communicate AI limitations to users.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
    "LLM10": {
        "title": "Model Theft",
        "recommendation": "Implement access controls, use watermarking, monitor for extraction attempts, rate-limit API access, and restrict model output verbosity.",
        "references": [
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
        ],
    },
}


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
    owasp: list["OWASPCategory"] = field(default_factory=list)  # OWASP LLM Top 10 mapping
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "technique": self.technique,
            "payload": self.payload,
            "response": self.response,
            "target": self.target,
            "details": self.details,
            "reason": self.reason,
            "owasp": [cat.id for cat in self.owasp] if self.owasp else [],
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanMetadata:
    """Metadata about the scan session for reports."""

    session_id: str | None = None
    session_name: str | None = None
    target: str = ""
    start_time: datetime | None = None
    end_time: datetime | None = None
    modules_run: list[str] = field(default_factory=list)
    risk_score: float = 0.0


class Reporter:
    """
    Handles output formatting and report generation.
    """

    def __init__(self):
        self.findings: list[Finding] = []
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self.metadata: ScanMetadata | None = None

    def start(self) -> None:
        """Mark scan start time"""
        self.start_time = datetime.now()

    def end(self) -> None:
        """Mark scan end time"""
        self.end_time = datetime.now()

    def add_finding(self, finding: Finding) -> None:
        """Add a finding"""
        self.findings.append(finding)

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-10 scale)."""
        total_weight = sum(SEVERITY_WEIGHTS.get(f.severity.value, 0) for f in self.findings)
        return min(10.0, total_weight / 5.0)

    def get_risk_level(self, score: float) -> str:
        """Classify risk level from score."""
        if score >= 8:
            return "Critical"
        elif score >= 5:
            return "High"
        elif score >= 2:
            return "Medium"
        else:
            return "Low"

    def get_owasp_coverage(self) -> dict[str, dict[str, Any]]:
        """Build OWASP LLM Top 10 coverage map."""
        all_categories = [f"LLM{i:02d}" for i in range(1, 11)]
        coverage: dict[str, dict[str, Any]] = {}

        for cat_id in all_categories:
            coverage[cat_id] = {
                "title": OWASP_REMEDIATION.get(cat_id, {}).get("title", "Unknown"),
                "tested": False,
                "findings_count": 0,
                "max_severity": "info",
            }

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        for finding in self.findings:
            if finding.owasp:
                for cat in finding.owasp:
                    cat_id = cat.id if hasattr(cat, "id") else str(cat)
                    if cat_id in coverage:
                        coverage[cat_id]["tested"] = True
                        coverage[cat_id]["findings_count"] += 1
                        current_max = coverage[cat_id]["max_severity"]
                        if severity_rank.get(finding.severity.value, 4) < severity_rank.get(
                            current_max, 4
                        ):
                            coverage[cat_id]["max_severity"] = finding.severity.value

        return coverage

    def generate_executive_summary(self) -> str:
        """Generate executive summary text."""
        if not self.findings:
            return "No vulnerabilities were identified during this assessment. The target appears to have adequate security controls in place for the tested attack vectors."

        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)

        counts = dict.fromkeys(Severity, 0)
        for f in self.findings:
            counts[f.severity] += 1

        total = len(self.findings)
        parts = []

        parts.append(
            f"This assessment identified {total} {'vulnerabilities' if total != 1 else 'vulnerability'} "
            f"with an overall risk score of {risk_score:.1f}/10 ({risk_level})."
        )

        severity_parts = []
        if counts[Severity.CRITICAL]:
            severity_parts.append(f"{counts[Severity.CRITICAL]} critical")
        if counts[Severity.HIGH]:
            severity_parts.append(f"{counts[Severity.HIGH]} high")
        if counts[Severity.MEDIUM]:
            severity_parts.append(f"{counts[Severity.MEDIUM]} medium")
        if counts[Severity.LOW]:
            severity_parts.append(f"{counts[Severity.LOW]} low")

        if severity_parts:
            parts.append(f"Breakdown: {', '.join(severity_parts)} severity findings.")

        if risk_score >= 8:
            parts.append(
                "Immediate remediation is strongly recommended. The target is highly vulnerable to AI-specific attacks."
            )
        elif risk_score >= 5:
            parts.append(
                "Significant vulnerabilities were found. Prioritize remediation of high and critical findings."
            )
        elif risk_score >= 2:
            parts.append(
                "Moderate risk detected. Review and address findings based on severity and business impact."
            )
        else:
            parts.append(
                "Low risk detected. Minor findings should be reviewed as part of regular security maintenance."
            )

        return " ".join(parts)

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

        console.print(
            Panel(
                f"[bold]{finding.title}[/bold]\n\n"
                f"[dim]Technique:[/dim] {finding.technique}\n"
                f"{owasp_line}"
                f"[dim]Reason:[/dim] {finding.reason}\n"
                f"[dim]Payload:[/dim] {finding.payload[:100]}...\n"
                f"[dim]Response:[/dim] {finding.response[:200]}...",
                title=f"[{color}]{finding.severity.value.upper()}[/{color}]",
                border_style=color,
            )
        )

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
                table.add_row(f"[{color}]{severity.value.upper()}[/{color}]", str(counts[severity]))

        console.print(table)

    def export_json(self, filepath: str) -> None:
        """Export findings to JSON with metadata, OWASP coverage, and executive summary"""
        risk_score = self.calculate_risk_score()

        data: dict[str, Any] = {
            "scan_info": {
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "total_findings": len(self.findings),
                "risk_score": risk_score,
                "risk_level": self.get_risk_level(risk_score),
            },
            "executive_summary": self.generate_executive_summary(),
            "owasp_coverage": self.get_owasp_coverage(),
            "findings": [f.to_dict() for f in self.findings],
        }

        if self.metadata:
            data["scan_info"]["session_id"] = self.metadata.session_id
            data["scan_info"]["session_name"] = self.metadata.session_name
            data["scan_info"]["target"] = self.metadata.target
            data["scan_info"]["modules_run"] = self.metadata.modules_run

        Path(filepath).write_text(json.dumps(data, indent=2))

    def export_html(self, filepath: str) -> None:
        """Export findings to enhanced HTML report"""

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
            Severity.INFO: 4,
        }

        for target in findings_by_target:
            findings_by_target[target].sort(key=lambda f: severity_order.get(f.severity, 99))

        # Risk score and executive summary
        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)
        executive_summary = self.generate_executive_summary()
        owasp_coverage = self.get_owasp_coverage()

        # Build metadata header HTML
        metadata_html = ""
        if self.metadata:
            meta = self.metadata
            duration = ""
            if meta.start_time and meta.end_time:
                delta = meta.end_time - meta.start_time
                minutes = int(delta.total_seconds() // 60)
                seconds = int(delta.total_seconds() % 60)
                duration = f"{minutes}m {seconds}s"
            modules_str = ", ".join(meta.modules_run) if meta.modules_run else "N/A"
            metadata_html = f"""
            <div class="metadata">
                <div class="metadata-item"><strong>Session:</strong> {self._escape_html(meta.session_name or 'N/A')}</div>
                <div class="metadata-item"><strong>Target:</strong> {self._escape_html(meta.target or 'N/A')}</div>
                <div class="metadata-item"><strong>Modules:</strong> {self._escape_html(modules_str)}</div>
                <div class="metadata-item"><strong>Duration:</strong> {duration or 'N/A'}</div>
                <div class="metadata-item"><strong>Date:</strong> {(meta.start_time.strftime('%Y-%m-%d %H:%M') if meta.start_time else 'N/A')}</div>
            </div>
            """

        # Build executive summary HTML
        risk_color = {
            "Critical": "#ff4757",
            "High": "#ffa502",
            "Medium": "#3742fa",
            "Low": "#888",
        }.get(risk_level, "#888")
        risk_pct = min(100, risk_score * 10)
        exec_summary_html = f"""
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="risk-gauge">
                <div class="risk-label">Risk Score: <span style="color: {risk_color}; font-weight: bold;">{risk_score:.1f}/10 ({risk_level})</span></div>
                <div class="risk-bar-bg">
                    <div class="risk-bar-fill" style="width: {risk_pct}%; background: {risk_color};"></div>
                </div>
            </div>
            <p class="exec-text">{self._escape_html(executive_summary)}</p>
            <div class="key-stats">
                <span class="key-stat">Total Findings: <strong>{len(self.findings)}</strong></span>
                <span class="key-stat">Targets: <strong>{len(findings_by_target)}</strong></span>
            </div>
        </div>
        """

        # Build severity chart HTML (CSS horizontal bars)
        total_findings = max(len(self.findings), 1)
        chart_html = """<div class="severity-chart"><h2>Severity Distribution</h2>"""
        chart_items = [
            ("Critical", counts[Severity.CRITICAL], "#ff4757"),
            ("High", counts[Severity.HIGH], "#ffa502"),
            ("Medium", counts[Severity.MEDIUM], "#3742fa"),
            ("Low", counts[Severity.LOW], "#888"),
            ("Info", counts[Severity.INFO], "#555"),
        ]
        for label, count, color in chart_items:
            pct = (count / total_findings * 100) if count > 0 else 0
            chart_html += f"""
            <div class="chart-row">
                <span class="chart-label">{label}</span>
                <div class="chart-bar-bg">
                    <div class="chart-bar-fill" style="width: {pct}%; background: {color};"></div>
                </div>
                <span class="chart-count">{count}</span>
            </div>"""
        chart_html += "</div>"

        # Build OWASP coverage grid
        owasp_html = """<div class="owasp-coverage"><h2>OWASP LLM Top 10 Coverage</h2><div class="owasp-grid">"""
        for cat_id, info in owasp_coverage.items():
            if info["findings_count"] > 0:
                card_class = "owasp-card vulnerable"
                status_icon = "&#x2717;"  # ✗
                status_text = (
                    f"{info['findings_count']} finding{'s' if info['findings_count'] > 1 else ''}"
                )
            elif info["tested"]:
                card_class = "owasp-card clean"
                status_icon = "&#x2713;"  # ✓
                status_text = "Clean"
            else:
                card_class = "owasp-card not-tested"
                status_icon = "&#x2014;"  # —
                status_text = "Not tested"
            owasp_html += f"""
            <div class="{card_class}">
                <div class="owasp-card-id">{cat_id}</div>
                <div class="owasp-card-title">{self._escape_html(info['title'])}</div>
                <div class="owasp-card-status">{status_icon} {status_text}</div>
            </div>"""
        owasp_html += "</div></div>"

        # Generate findings HTML
        findings_html = ""

        for target, target_findings in findings_by_target.items():
            findings_html += f'<div class="target-group"><h3>{self._escape_html(target)}</h3>'

            for finding in target_findings:
                severity_class = finding.severity.value
                # Generate OWASP badges
                owasp_badges = ""
                if finding.owasp:
                    owasp_badges = (
                        '<div class="owasp-tags">'
                        + "".join(
                            f'<span class="owasp-badge">{cat.id}</span>' for cat in finding.owasp
                        )
                        + "</div>"
                    )
                findings_html += f"""
                <div class="finding {severity_class}">
                    <div class="finding-header">
                        <span class="severity-badge {severity_class}">{finding.severity.value.upper()}</span>
                        <span class="finding-title">{self._escape_html(finding.title)}</span>
                        <span class="technique-badge">{self._escape_html(finding.technique)}</span>
                    </div>
                    <div class="finding-body">
                        {owasp_badges}
                        {f'<div class="finding-field reason"><strong>Reason:</strong> {self._escape_html(finding.reason)}</div>' if finding.reason else ''}

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

                        {f'<div class="finding-field"><strong>Details:</strong> {self._escape_html(finding.details)}</div>' if finding.details else ''}
                    </div>
                </div>
                """
            findings_html += "</div>"

        # Build remediation section
        remediation_html = ""
        affected_categories = {
            cat_id for cat_id, info in owasp_coverage.items() if info["findings_count"] > 0
        }
        if affected_categories:
            remediation_html = """<div class="remediation"><h2>Remediation Recommendations</h2>"""
            for cat_id in sorted(affected_categories):
                rec = OWASP_REMEDIATION.get(cat_id, {})
                if rec:
                    remediation_html += f"""
                    <div class="remediation-item">
                        <h3>{cat_id}: {self._escape_html(rec.get('title', ''))}</h3>
                        <p>{self._escape_html(rec.get('recommendation', ''))}</p>
                    </div>"""
            remediation_html += "</div>"

        # Build footer
        from aix import __version__

        footer_html = f"""
        <footer>
            Generated by AIX v{__version__} - AI eXploit Framework<br>
            {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
        """

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

        .metadata {{
            display: flex;
            flex-wrap: wrap;
            gap: 1.5rem;
            margin-top: 1rem;
            justify-content: center;
        }}
        .metadata-item {{
            color: #aaa;
            font-size: 0.9rem;
        }}
        .metadata-item strong {{
            color: #00d4ff;
        }}

        .executive-summary {{
            background: #1a1a2a;
            border: 1px solid #2a2a3a;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        .executive-summary h2 {{
            color: #00d4ff;
            margin-bottom: 1rem;
            border-bottom: 1px solid #2a2a3a;
            padding-bottom: 0.5rem;
        }}
        .risk-gauge {{
            margin-bottom: 1rem;
        }}
        .risk-label {{
            font-size: 1.1rem;
            margin-bottom: 0.5rem;
        }}
        .risk-bar-bg {{
            background: #2a2a3a;
            border-radius: 4px;
            height: 12px;
            overflow: hidden;
        }}
        .risk-bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }}
        .exec-text {{
            color: #ccc;
            margin: 1rem 0;
        }}
        .key-stats {{
            display: flex;
            gap: 2rem;
        }}
        .key-stat {{
            color: #aaa;
            font-size: 0.9rem;
        }}
        .key-stat strong {{
            color: #00d4ff;
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

        .severity-chart {{
            background: #1a1a2a;
            border: 1px solid #2a2a3a;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        .severity-chart h2 {{
            color: #00d4ff;
            margin-bottom: 1rem;
            border-bottom: 1px solid #2a2a3a;
            padding-bottom: 0.5rem;
        }}
        .chart-row {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 0.5rem;
        }}
        .chart-label {{
            width: 70px;
            text-align: right;
            color: #aaa;
            font-size: 0.85rem;
        }}
        .chart-bar-bg {{
            flex: 1;
            background: #2a2a3a;
            border-radius: 4px;
            height: 20px;
            overflow: hidden;
        }}
        .chart-bar-fill {{
            height: 100%;
            border-radius: 4px;
        }}
        .chart-count {{
            width: 30px;
            text-align: right;
            font-weight: bold;
            color: #e0e0e0;
        }}

        .owasp-coverage {{
            margin-bottom: 2rem;
        }}
        .owasp-coverage h2 {{
            color: #00d4ff;
            margin-bottom: 1rem;
            border-bottom: 1px solid #2a2a3a;
            padding-bottom: 0.5rem;
        }}
        .owasp-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.75rem;
        }}
        .owasp-card {{
            background: #1a1a2a;
            border: 1px solid #2a2a3a;
            border-radius: 6px;
            padding: 1rem;
        }}
        .owasp-card.vulnerable {{
            border-color: #ff4757;
        }}
        .owasp-card.clean {{
            border-color: #2ed573;
        }}
        .owasp-card.not-tested {{
            border-color: #444;
            opacity: 0.6;
        }}
        .owasp-card-id {{
            font-family: monospace;
            font-weight: bold;
            color: #00d4ff;
            font-size: 0.85rem;
        }}
        .owasp-card-title {{
            font-size: 0.8rem;
            color: #ccc;
            margin: 0.25rem 0;
        }}
        .owasp-card-status {{
            font-size: 0.75rem;
            color: #888;
        }}
        .owasp-card.vulnerable .owasp-card-status {{ color: #ff4757; }}
        .owasp-card.clean .owasp-card-status {{ color: #2ed573; }}

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

        details summary {{
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

        .remediation {{
            background: #1a1a2a;
            border: 1px solid #2a2a3a;
            border-radius: 8px;
            padding: 2rem;
            margin-top: 2rem;
        }}
        .remediation h2 {{
            color: #00d4ff;
            margin-bottom: 1rem;
            border-bottom: 1px solid #2a2a3a;
            padding-bottom: 0.5rem;
        }}
        .remediation-item {{
            margin-bottom: 1.5rem;
        }}
        .remediation-item h3 {{
            color: #ffa502;
            font-size: 1rem;
            margin-bottom: 0.5rem;
        }}
        .remediation-item p {{
            color: #ccc;
            font-size: 0.9rem;
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
            <div class="logo">&#x2588;&#x2580;&#x2588; &#x2588; &#x2580;&#x2584;&#x2580;<br>&#x2588;&#x2580;&#x2588; &#x2588; &#x2588; &#x2588;</div>
            <div class="subtitle">AI Security Testing Report</div>
            {metadata_html}
        </header>

        {exec_summary_html}

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

        {chart_html}

        {owasp_html}

        <div class="findings">
            <h2>Findings</h2>
            {findings_html if findings_html else '<p style="color: #888;">No findings to display.</p>'}
        </div>

        {remediation_html}

        {footer_html}
    </div>
</body>
</html>
        """

        Path(filepath).write_text(html)

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
