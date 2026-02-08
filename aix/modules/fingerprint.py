"""
AIX Fingerprint Module

Advanced probabilistic model fingerprinting mechanism.
Identifies LLMs by analyzing their responses to specific "Shibboleth" questions,
refusal styles, and identity claims.

Supports two strategies:
- Embedding-based (requires `sentence-transformers`): Uses cosine similarity against
  pre-enrolled model signatures for 95%+ accuracy.
- Pattern-based (default fallback): Uses regex matching and softmax scoring.

Install `pip install aix-framework[ml]` to enable embedding-based fingerprinting.
"""

import asyncio
import json
import math
import re
from pathlib import Path

from rich.console import Console
from rich.progress import track
from rich.table import Table

from aix.core.connector import APIConnector, RequestConnector

console = Console()


class FingerprintScanner:
    """
    Probabilistic Fingerprinting Engine.

    Analyses model responses against a database of known signatures to
    determine the most likely model family and version.
    """

    def __init__(
        self,
        target: str,
        connector=None,
        parsed_request=None,
        verbose=False,
        console=None,
        quiet=False,
        **kwargs,
    ):
        self.target = target
        self.connector = connector
        self.parsed_request = parsed_request
        self.verbose = verbose
        self.quiet = quiet
        # Use shared console or create one
        if console:
            self.console = console
        else:
            self.console = Console()
        self.config = kwargs
        self.show_progress = kwargs.get("show_progress", True)
        self.db = self._load_db()
        self.results = {}
        self.scores = dict.fromkeys(self.db.get("signatures", {}), 0.0)
        self.penalty_history = {model: [] for model in self.scores}  # Track why points were lost
        self.response_history = []

        # Initialize probabilities (uniform prior)
        num_models = len(self.scores)
        self.probabilities = dict.fromkeys(self.scores, 1.0 / num_models)

        # Embedding-based fingerprinting (auto-detected)
        self.embedding_available = self._check_embedding_deps()
        self._encoder = None  # lazy-loaded
        self.embedding_probes = []
        self.signature_db = {}
        self.response_pairs = []  # (query, response) tuples for embedding
        if self.embedding_available:
            self.embedding_probes = self._load_embedding_probes()
            self.signature_db = self._load_signature_db()

    def _load_db(self) -> dict:
        """Load fingerprint database"""
        try:
            path = Path(__file__).parent.parent / "payloads" / "fingerprint_db.json"
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            if hasattr(self, "console") and not getattr(self, "quiet", False):
                self.console.print(f"[red][-] Failed to load fingerprint DB: {e}[/red]")
            return {"questions": [], "signatures": {}}

    # --- Embedding support methods ---

    @staticmethod
    def _check_embedding_deps() -> bool:
        """Check if sentence-transformers is available. Never raises."""
        try:
            import sentence_transformers  # noqa: F401

            return True
        except Exception:
            return False

    def _load_embedding_probes(self) -> list:
        """Load embedding probe queries from fingerprint_probes.json."""
        try:
            path = Path(__file__).parent.parent / "payloads" / "fingerprint_probes.json"
            with open(path) as f:
                return json.load(f)
        except Exception:
            return []

    def _load_signature_db(self) -> dict:
        """Load embedding signature database from fingerprint_embeddings.json."""
        try:
            path = Path(__file__).parent.parent / "payloads" / "fingerprint_embeddings.json"
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}

    def _get_encoder(self):
        """Lazy-load the SentenceTransformer encoder."""
        if self._encoder is None:
            from sentence_transformers import SentenceTransformer

            self._encoder = SentenceTransformer("all-MiniLM-L6-v2")
        return self._encoder

    def _compute_signature(self) -> list:
        """
        Compute an embedding signature from collected (query, response) pairs.

        Each pair is encoded as "query: {q} [SEP] response: {r}".
        All embeddings are mean-pooled and L2-normalized to a 384-dim vector.
        """
        if not self.response_pairs:
            return []

        encoder = self._get_encoder()

        # Build input texts with weights
        texts = []
        weights = []
        probe_weights = {p["id"]: p.get("weight", 1.0) for p in self.embedding_probes}

        for probe_id, query, response in self.response_pairs:
            texts.append(f"query: {query} [SEP] response: {response}")
            weights.append(probe_weights.get(probe_id, 1.0))

        # Encode all texts
        embeddings = encoder.encode(texts, show_progress_bar=False)

        # Weighted mean-pool
        total_weight = sum(weights)
        dim = len(embeddings[0])
        pooled = [0.0] * dim
        for i, emb in enumerate(embeddings):
            w = weights[i] / total_weight
            for j in range(dim):
                pooled[j] += float(emb[j]) * w

        # L2-normalize
        norm = math.sqrt(sum(x * x for x in pooled))
        if norm > 0:
            pooled = [x / norm for x in pooled]

        return pooled

    @staticmethod
    def cosine_similarity(a: list, b: list) -> float:
        """Compute cosine similarity between two vectors. Pure Python, no numpy needed."""
        if not a or not b or len(a) != len(b):
            return 0.0

        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot / (norm_a * norm_b)

    def _match_embedding(self, signature: list) -> list:
        """
        Match a computed signature against all populated entries in the signature DB.

        Returns list of (model_name, similarity_score) sorted descending.
        """
        if not signature or not self.signature_db.get("models"):
            return []

        scores = []
        for model_key, model_info in self.signature_db["models"].items():
            ref_sig = model_info.get("signature", [])
            if not ref_sig:
                continue  # Skip models without enrolled signatures
            sim = self.cosine_similarity(signature, ref_sig)
            scores.append((model_key, sim))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    def _print_embedding_report(self, scores: list) -> str | None:
        """
        Print embedding-based fingerprint results as a Rich table.

        Returns the winning model name if top similarity > 0.70, else None.
        """
        if not scores:
            return None

        table = Table(
            title="Embedding Fingerprint Analysis",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Model", style="cyan")
        table.add_column("Similarity", justify="right", style="green")
        table.add_column("Family", style="white")

        # Show top 5
        for model_key, sim in scores[:5]:
            model_info = self.signature_db["models"].get(model_key, {})
            family = model_info.get("family", "Unknown")
            display = model_info.get("display_name", model_key)

            pct = f"{sim * 100:.1f}%"
            color = "green" if sim > 0.70 else "yellow" if sim > 0.50 else "red"
            table.add_row(display, f"[{color}]{pct}[/]", family)

        if not self.quiet:
            self.console.print()
            self.console.print(table)

        # Return winner if above threshold
        if scores[0][1] > 0.70:
            winner_key = scores[0][0]
            display = self.signature_db["models"][winner_key].get("display_name", winner_key)
            family = self.signature_db["models"][winner_key].get("family", "Unknown")
            if not self.quiet:
                self.console.print(f"[bold green][+] Embedding ID: {display} ({family})[/]")
            return winner_key
        return None

    async def _run_embedding(self) -> str | None:
        """
        Run embedding-based fingerprinting.

        1. Send 8 probes from fingerprint_probes.json
        2. Collect (query, response) pairs
        3. Compute embedding signature
        4. Match against signature DB
        5. Print report and return winner or None
        """
        if not self.embedding_probes:
            return None

        if not self.quiet:
            self.console.print("[cyan][*] Running embedding-based fingerprinting...[/cyan]")

        # Send probes and collect responses
        for probe in track(
            self.embedding_probes,
            description="[bold cyan]Embedding probes... [/]",
            console=self.console,
            disable=not self.show_progress,
        ):
            response = await self._send_probe(probe)

            if response == "AUTH_FAILED":
                if not self.quiet:
                    self.console.print("[red][!] Embedding fingerprint aborted: auth failure[/red]")
                return None

            if response:
                self.response_pairs.append((probe["id"], probe["prompt"], response))
                await asyncio.sleep(0.5)

        if not self.response_pairs:
            return None

        # Compute signature and match
        signature = self._compute_signature()
        if not signature:
            return None

        scores = self._match_embedding(signature)
        return self._print_embedding_report(scores)

    # --- End embedding support ---

    async def _send_probe(self, question: dict) -> str:
        """Send a single probe question"""
        if not self.connector:
            # Create appropriate connector
            if self.parsed_request:
                # Use RequestConnector if parsed_request is available (for -r mode)
                self.connector = RequestConnector(
                    self.parsed_request,
                    proxy=self.config.get("proxy"),
                    cookies=self.config.get("cookies"),  # Ensure cookies flow
                    headers=self.config.get("headers"),
                    timeout=15,
                    console=self.console,
                )
            else:
                # Default to APIConnector
                self.connector = APIConnector(
                    self.target,
                    api_key=self.config.get("api_key"),
                    proxy=self.config.get("proxy"),
                    cookies=self.config.get("cookies"),  # Ensure cookies flow
                    headers=self.config.get("headers"),
                    timeout=15,
                    console=self.console,
                )

        try:
            response = await self.connector.send(question["prompt"])
            return response
        except Exception as e:
            # Check for auth failure (401)
            err = str(e)
            if "401" in err or "Unauthorized" in err or "Token has expired" in err:
                return "AUTH_FAILED"
            # Don't print to console directly as it breaks progress bar
            # console.print(f"[red]Probe failed: {e}[/red]")
            return ""

    def _analyze_response(self, response: str, weight: float):
        """Analyze a single response and update scores"""
        response_lower = response.lower()

        for model, signature in self.db["signatures"].items():
            model_score = 0.0

            # Check for patterns
            for pattern in signature.get("patterns", []):
                if re.search(pattern, response_lower):
                    model_score += 1.0

            # Check for refusal style
            if "refusal_style" in signature:
                if re.search(signature["refusal_style"], response_lower):
                    model_score += 2.0  # Stronger signal

            # Check for identity claim
            if "identity_claim" in signature:
                if re.search(signature["identity_claim"], response_lower):
                    model_score += 5.0  # Increased from 3.0 -> 5.0 (Definitive claim)

                    # EXCLUSION LOGIC:
                    # If model claims to be X (e.g. OpenAI), heavily penalize incompatible families
                    current_family = signature.get("family", "Unknown")
                    self._apply_exclusion(current_family)

            # Check for Anti-Patterns (Negative Scoring)
            for anti in signature.get("anti_patterns", []):
                if re.search(anti, response_lower):
                    penalty = 2.0  # Reduced from 5.0 to avoid over-penalizing context mentions
                    model_score -= penalty
                    self.penalty_history[model].append("Anti-Pattern")  # Track reason

            # Normalize and apply weight
            # We add to the raw score for this model
            self.scores[model] += model_score * weight

    def _apply_exclusion(self, confirmed_family: str):
        """Heavily penalize models from different families if we have a strong identity claim"""
        for model, sig in self.db["signatures"].items():
            if sig.get("family") != confirmed_family:
                self.scores[model] -= 10.0  # Massive penalty
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
        top_models = [m for m in sorted_models if m[1] > 0.01][:5]  # Top 5 with >1% prob

        table = Table(
            title="Pattern Fingerprint Analysis", show_header=True, header_style="bold magenta"
        )
        table.add_column("Likely Model", style="cyan")
        table.add_column("Probability", justify="right", style="green")
        table.add_column("Family", style="white")
        table.add_column("Confidence Evidence", style="dim")

        for model_key, prob in top_models:
            family = self.db["signatures"][model_key]["family"]
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

            table.add_row(model_key, f"[{color}]{prob_str}[/]", family, evidence)

        if not self.quiet:
            self.console.print()
            self.console.print(table)

        # Identify winner
        if top_models and top_models[0][1] > 0.4:
            winner = top_models[0][0]
            if not self.quiet:
                self.console.print(
                    f"[bold green][+] Primary ID: {winner} ({self.db['signatures'][winner]['family']})[/]"
                )
            return winner
        return None

    async def run(self):
        """Run the full fingerprinting process"""

        # Auto-select: embedding if deps available AND signatures populated
        has_signatures = any(
            m.get("signature") for m in self.signature_db.get("models", {}).values()
        )
        if self.embedding_available and has_signatures:
            result = await self._run_embedding()
            if result:
                return result
            # Fall through to pattern-based if embedding didn't produce a match

        # Existing pattern-based flow
        questions = self.db["questions"]

        # We can run these in parallel or serial. Serial is safer for rate limits.
        for q in track(
            questions,
            description="[bold cyan]Pattern probes...   [/]",
            console=self.console,
            disable=not self.show_progress,
        ):
            response = await self._send_probe(q)

            if self.verbose and not self.quiet and response and response != "AUTH_FAILED":
                self.console.print(f"[dim]Probe ({q['id']}) Response: {response[:100]}...[/dim]")

            # Check for critical auth failure
            if response == "AUTH_FAILED":
                # We can't print easily inside track without breaking it, but we can just stop
                # Or we can print using the progress object if we had access to it,
                # but 'track' hides the progress object.
                # Best is to break and warn after.
                self.auth_failed = True
                break

            if response:
                self.response_history.append((q["id"], response))
                self._analyze_response(response, q.get("weight", 1.0))
                # Small delay to be polite
                await asyncio.sleep(0.5)

        if hasattr(self, "auth_failed") and self.auth_failed:
            if not self.quiet:
                self.console.print(
                    "[red][!] Fingerprinting aborted due to Authentication Failure (401). Session likely expired.[/red]"
                )
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
