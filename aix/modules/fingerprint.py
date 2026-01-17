"""
AIX Fingerprint Module

Advanced probabilistic model fingerprinting mechanism.
Identifies LLMs by analyzing their responses to specific "Shibboleth" questions,
refusal styles, and identity claims.
"""

import json
import re
import asyncio
import math
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

from aix.core.connector import APIConnector, RequestConnector

console = Console()

class FingerprintScanner:
    """
    Probabilistic Fingerprinting Engine.
    
    Analyses model responses against a database of known signatures to 
    determine the most likely model family and version.
    """
    
    def __init__(self, target: str, connector=None, parsed_request=None, verbose=False, **kwargs):
        self.target = target
        self.connector = connector
        self.parsed_request = parsed_request
        self.verbose = verbose
        self.config = kwargs
        self.db = self._load_db()
        self.results = {}
        self.scores = {model: 0.0 for model in self.db.get('signatures', {})}
        self.penalty_history = {model: [] for model in self.scores} # Track why points were lost
        self.response_history = []
        
        # Initialize probabilities (uniform prior)
        num_models = len(self.scores)
        self.probabilities = {model: 1.0 / num_models for model in self.scores}

    def _load_db(self) -> dict:
        """Load fingerprint database"""
        try:
            path = Path(__file__).parent.parent / 'payloads' / 'fingerprint_db.json'
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            console.print(f"[red][-] Failed to load fingerprint DB: {e}[/red]")
            return {"questions": [], "signatures": {}}

    async def _send_probe(self, question: dict) -> str:
        """Send a single probe question"""
        if not self.connector:
            # Create appropriate connector
            if self.parsed_request:
                # Use RequestConnector if parsed_request is available (for -r mode)
                self.connector = RequestConnector(
                    self.parsed_request,
                    proxy=self.config.get('proxy'),
                    cookies=self.config.get('cookies'), # Ensure cookies flow
                    headers=self.config.get('headers'),
                    timeout=15
                )
            else:
                # Default to APIConnector
                self.connector = APIConnector(
                    self.target,
                    api_key=self.config.get('api_key'),
                    proxy=self.config.get('proxy'),
                    cookies=self.config.get('cookies'), # Ensure cookies flow
                    headers=self.config.get('headers'),
                    timeout=15
                )
            
        try:
            response = await self.connector.send(question['prompt'])
            return response
        except Exception as e:
            # Check for auth failure (401)
            err = str(e)
            if '401' in err or 'Unauthorized' in err or 'Token has expired' in err:
                return "AUTH_FAILED"
            # Don't print to console directly as it breaks progress bar
            # console.print(f"[red]Probe failed: {e}[/red]")
            return ""

    def _analyze_response(self, response: str, weight: float):
        """Analyze a single response and update scores"""
        response_lower = response.lower()
        
        for model, signature in self.db['signatures'].items():
            model_score = 0.0
            
            # Check for patterns
            for pattern in signature.get('patterns', []):
                if re.search(pattern, response_lower):
                    model_score += 1.0
            
            # Check for refusal style
            if 'refusal_style' in signature:
                if re.search(signature['refusal_style'], response_lower):
                    model_score += 2.0  # Stronger signal
            
            # Check for identity claim
            if 'identity_claim' in signature:
                 if re.search(signature['identity_claim'], response_lower):
                    model_score += 5.0 # Increased from 3.0 -> 5.0 (Definitive claim)
                    
                    # EXCLUSION LOGIC:
                    # If model claims to be X (e.g. OpenAI), heavily penalize incompatible families
                    current_family = signature.get('family', 'Unknown')
                    self._apply_exclusion(current_family)

            # Check for Anti-Patterns (Negative Scoring)
            for anti in signature.get('anti_patterns', []):
                if re.search(anti, response_lower):
                    penalty = 2.0  # Reduced from 5.0 to avoid over-penalizing context mentions
                    model_score -= penalty
                    self.penalty_history[model].append("Anti-Pattern") # Track reason

            # Normalize and apply weight
            # We add to the raw score for this model
            self.scores[model] += model_score * weight

    def _apply_exclusion(self, confirmed_family: str):
        """Heavily penalize models from different families if we have a strong identity claim"""
        for model, sig in self.db['signatures'].items():
            if sig.get('family') != confirmed_family:
                self.scores[model] -= 10.0 # Massive penalty
                self.penalty_history[model].append("Exclusion")

    def _calculate_probabilities(self):
        """Convert raw scores to probabilities using Softmax"""
        # Softmax: exp(score) / sum(exp(scores))
        # Stabilize by subtracting max score to avoid overflow
        if not self.scores:
            return
            
        scores = self.scores
        max_score = max(scores.values())
        
        # Calculate exp values
        exps = {m: math.exp(s - max_score) for m, s in scores.items()}
        total_exp = sum(exps.values())
        
        if total_exp == 0:
            return

        for model in self.scores:
            self.probabilities[model] = exps[model] / total_exp

    def print_report(self):
        """Print the fingerprinting report"""
        
        # Sort by probability
        sorted_models = sorted(self.probabilities.items(), key=lambda x: x[1], reverse=True)
        top_models = [m for m in sorted_models if m[1] > 0.01][:5] # Top 5 with >1% prob
        
        table = Table(title="🧬 Fingerprint Analysis", show_header=True, header_style="bold magenta")
        table.add_column("Likely Model", style="cyan")
        table.add_column("Probability", justify="right", style="green")
        table.add_column("Family", style="white")
        table.add_column("Confidence Evidence", style="dim")

        for model_key, prob in top_models:
            family = self.db['signatures'][model_key]['family']
            score = self.scores[model_key]
            
            # Create evidence string based on penalties/score
            evidence = f"Score: {score:.1f}"
            penalties = self.penalty_history.get(model_key, [])
            if penalties:
                unique_penalties = list(set(penalties))
                bad_stuff = ", ".join(unique_penalties[:2])
                evidence += f" (Penalties: {bad_stuff})"
            
            prob_str = f"{prob*100:.1f}%"
            # Color logic
            color = "green" if prob > 0.5 else "yellow" if prob > 0.2 else "red"
            
            table.add_row(
                model_key, 
                f"[{color}]{prob_str}[/]", 
                family, 
                evidence
            )

        console.print()
        console.print(table)
        
        # Identify winner
        if top_models and top_models[0][1] > 0.4:
            winner = top_models[0][0]
            console.print(f"[bold green][+] Primary ID: {winner} ({self.db['signatures'][winner]['family']})[/]")
            return winner
        return None

    async def run(self):
        """Run the full fingerprinting process"""
        # console.print(f"[cyan][*] Running Advanced Fingerprinting ({len(self.db['questions'])} probes)...[/cyan]")
        
        # Create progress bar
        questions = self.db['questions']
        
        # We can run these in parallel or serial. Serial is safer for rate limits.
        for q in track(questions, description="Fingerprinting..."):
            response = await self._send_probe(q)
            
            if self.verbose and response and response != "AUTH_FAILED":
                console.print(f"[dim]Probe ({q['id']}) Response: {response[:100]}...[/dim]")
            
            # Check for critical auth failure
            if response == "AUTH_FAILED":
                # We can't print easily inside track without breaking it, but we can just stop
                # Or we can print using the progress object if we had access to it, 
                # but 'track' hides the progress object.
                # Best is to break and warn after.
                self.auth_failed = True
                break
                
            if response:
                self.response_history.append((q['id'], response))
                self._analyze_response(response, q.get('weight', 1.0))
                # Small delay to be polite
                await asyncio.sleep(0.5)
        
        if hasattr(self, 'auth_failed') and self.auth_failed:
             console.print("[red][!] Fingerprinting aborted due to Authentication Failure (401). Session likely expired.[/red]")
             return None
        
        self._calculate_probabilities()
        return self.print_report()

# Standalone run
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python fingerprint.py <url>")
        sys.exit(1)
    
    scanner = FingerprintScanner(sys.argv[1])
    asyncio.run(scanner.run())
