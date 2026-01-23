"""
AIX Database

SQLite database for storing scan results and profiles.
Like NetExec's database functionality.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

console = Console()


class AIXDatabase:
    """
    Database for storing AIX scan results and target profiles.
    """

    def __init__(self, db_path: str | None = None):
        if db_path is None:
            # Default to ~/.aix/aix.db
            aix_dir = Path.home() / '.aix'
            aix_dir.mkdir(exist_ok=True)
            db_path = str(aix_dir / 'aix.db')

        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database tables"""
        cursor = self.conn.cursor()

        # Results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                technique TEXT NOT NULL,
                result TEXT NOT NULL,
                payload TEXT,
                response TEXT,
                severity TEXT,
                reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Migration: Check if reason column exists
        try:
             cursor.execute("SELECT reason FROM results LIMIT 1")
        except sqlite3.OperationalError:
             # Column missing, add it
             console.print("[yellow][*] Migrating database: Adding 'reason' column to results table[/yellow]")
             cursor.execute("ALTER TABLE results ADD COLUMN reason TEXT")

        # Profiles table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                endpoint TEXT,
                method TEXT DEFAULT 'POST',
                auth_type TEXT,
                auth_value TEXT,
                model TEXT,
                filters TEXT,
                rate_limit INTEGER,
                waf TEXT,
                websocket TEXT,
                request_template TEXT,
                response_path TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Payloads table (for custom payloads)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                payload TEXT NOT NULL,
                description TEXT,
                success_indicators TEXT,
                severity TEXT DEFAULT 'high',
                enabled INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        self.conn.commit()

    # ========================================================================
    # Results
    # ========================================================================

    def add_result(
        self,
        target: str,
        module: str,
        technique: str,
        result: str,
        payload: str = "",
        response: str = "",
        severity: str = "high",
        reason: str = "",
        dedup_payload: str | None = None,
    ) -> int:
        """
        Add a scan result. 
        Updates existing result if matched.
        If dedup_payload is provided (indicating randomized variants), duplicates are checked 
        by (target, module, technique) ignoring the payload string.
        Otherwise, (target, module, technique, payload) must match.
        """
        cursor = self.conn.cursor()

        existing = None
        
        if dedup_payload:
            # Randomized evasion active: Dedup by technique name only.
            # We want to update the latest entry for this technique.
            cursor.execute("""
                SELECT id FROM results 
                WHERE target = ? AND module = ? AND technique = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (target, module, technique))
            existing = cursor.fetchone()
        else:
            # Standard Strict Dedup: Payload must match exactly
            cursor.execute("""
                SELECT id FROM results 
                WHERE target = ? AND module = ? AND technique = ? AND payload = ?
            """, (target, module, technique, payload))
            existing = cursor.fetchone()
        
        if existing:
            # Update existing result
            row_id = existing[0]
            cursor.execute("""
                UPDATE results 
                SET result = ?, payload = ?, response = ?, severity = ?, reason = ?, timestamp = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (result, payload, response, severity, reason, row_id))
            self.conn.commit()
            return row_id
        else:
            # Insert new result
            cursor.execute("""
                INSERT INTO results (target, module, technique, result, payload, response, severity, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (target, module, technique, result, payload, response, severity, reason))
            self.conn.commit()
            return cursor.lastrowid


    def get_results(
        self,
        target: str | None = None,
        module: str | None = None,
        result: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get scan results with optional filters"""
        cursor = self.conn.cursor()

        query = "SELECT * FROM results WHERE 1=1"
        params = []

        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")

        if module:
            query += " AND module = ?"
            params.append(module)

        if result:
            query += " AND result = ?"
            params.append(result)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def display_results(self, results: list[dict[str, Any]]) -> None:
        """Display results in a nice table"""
        if not results:
            console.print("[dim]No results found[/dim]")
            return

        table = Table(title="AIX Results")
        table.add_column("ID", style="dim", width=6)
        table.add_column("Target", style="cyan", max_width=30)
        table.add_column("Module", style="blue")
        table.add_column("Technique", max_width=25)
        table.add_column("Result")
        table.add_column("Severity")
        table.add_column("Date", style="dim")

        for r in results:
            # Color result
            result_str = r['result']
            if result_str == 'success':
                result_str = "[green]Pwn3d![/green]"
            elif result_str == 'partial':
                result_str = "[yellow]Partial[/yellow]"
            elif result_str == 'blocked':
                result_str = "[red]Blocked[/red]"

            # Color severity
            severity_str = r.get('severity', 'unknown')
            severity_colors = {
                'critical': 'red',
                'high': 'yellow',
                'medium': 'blue',
                'low': 'dim',
            }
            severity_color = severity_colors.get(severity_str, 'white')
            severity_str = f"[{severity_color}]{severity_str}[/{severity_color}]"

            # Truncate target
            target = r['target']
            if len(target) > 28:
                target = target[:25] + "..."

            table.add_row(
                str(r['id']),
                target,
                r['module'],
                r['technique'],
                result_str,
                severity_str,
                r['timestamp'][:10] if r['timestamp'] else "",
            )

        console.print(table)

    def clear(self) -> None:
        """Clear all results"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM results")
        self.conn.commit()

    # ========================================================================
    # Profiles
    # ========================================================================

    def save_profile(self, name: str, profile_data: dict[str, Any]) -> int:
        """Save a target profile"""
        cursor = self.conn.cursor()

        # Convert lists/dicts to JSON
        filters_json = json.dumps(profile_data.get('filters', []))
        template_json = json.dumps(profile_data.get('request_template', {}))

        cursor.execute("""
            INSERT OR REPLACE INTO profiles 
            (name, url, endpoint, method, auth_type, auth_value, model, 
             filters, rate_limit, waf, websocket, request_template, response_path, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            name,
            profile_data.get('url', ''),
            profile_data.get('endpoint'),
            profile_data.get('method', 'POST'),
            profile_data.get('auth_type'),
            profile_data.get('auth_value'),
            profile_data.get('model'),
            filters_json,
            profile_data.get('rate_limit'),
            profile_data.get('waf'),
            profile_data.get('websocket'),
            template_json,
            profile_data.get('response_path'),
        ))
        self.conn.commit()
        return cursor.lastrowid

    def get_profile(self, name: str) -> dict[str, Any] | None:
        """Get a profile by name"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM profiles WHERE name = ?", (name,))
        row = cursor.fetchone()

        if row:
            profile = dict(row)
            # Parse JSON fields
            profile['filters'] = json.loads(profile.get('filters', '[]'))
            profile['request_template'] = json.loads(profile.get('request_template', '{}'))
            return profile

        return None

    def list_profiles(self) -> list[dict[str, Any]]:
        """List all profiles"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT name, url, model, waf, created_at FROM profiles ORDER BY name")
        return [dict(row) for row in cursor.fetchall()]

    def delete_profile(self, name: str) -> bool:
        """Delete a profile"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM profiles WHERE name = ?", (name,))
        self.conn.commit()
        return cursor.rowcount > 0

    # ========================================================================
    # Export
    # ========================================================================

    def export_html(
        self,
        filepath: str,
        target: str | None = None,
        module: str | None = None,
    ) -> None:
        """Export results to HTML report"""
        from aix.core.reporter import Finding, Reporter, Severity

        results = self.get_results(target=target, module=module, limit=1000)

        reporter = Reporter()

        for r in results:
            if r['result'] == 'success':
                severity = Severity(r.get('severity', 'high'))
                finding = Finding(
                    title=f"{r['technique']} - Vulnerable",
                    severity=severity,
                    technique=r['technique'],
                    payload=r.get('payload', ''),
                    response=r.get('response', ''),
                    target=r['target'],
                    reason=r.get('reason', ''),
                )
                reporter.add_finding(finding)

        reporter.export_html(filepath)

    def export_json(self, filepath: str) -> None:
        """Export all results to JSON"""
        results = self.get_results(limit=10000)
        profiles = self.list_profiles()

        data = {
            'exported_at': datetime.now().isoformat(),
            'results': results,
            'profiles': profiles,
        }

        Path(filepath).write_text(json.dumps(data, indent=2, default=str))

    def close(self) -> None:
        """Close database connection"""
        self.conn.close()
