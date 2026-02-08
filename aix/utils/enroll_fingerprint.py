"""
AIX Fingerprint Enrollment Utility

Populates the fingerprint_embeddings.json signature database by sending probes
to a known model endpoint, computing the embedding signature, and merging it
into the database.

Usage:
    python -m aix.utils.enroll_fingerprint \
        --target https://api.openai.com/v1/chat/completions \
        --key sk-xxx --model-name gpt-4o --family OpenAI

    # Average over multiple runs for stability
    python -m aix.utils.enroll_fingerprint \
        --target https://api.openai.com/v1/chat/completions \
        --key sk-xxx --model-name gpt-4o --family OpenAI --runs 3
"""

import argparse
import asyncio
import json
import math
import sys
from pathlib import Path


def _get_payloads_dir() -> Path:
    return Path(__file__).parent.parent / "payloads"


def _load_probes() -> list:
    path = _get_payloads_dir() / "fingerprint_probes.json"
    with open(path) as f:
        return json.load(f)


def _load_signature_db() -> dict:
    path = _get_payloads_dir() / "fingerprint_embeddings.json"
    with open(path) as f:
        return json.load(f)


def _save_signature_db(db: dict):
    path = _get_payloads_dir() / "fingerprint_embeddings.json"
    with open(path, "w") as f:
        json.dump(db, f, indent=2)
    print(f"[+] Saved signature database to {path}")


async def _send_probe(connector, prompt: str) -> str:
    try:
        return await connector.send(prompt)
    except Exception as e:
        print(f"  [!] Probe failed: {e}")
        return ""


def _compute_signature(encoder, probes: list, response_pairs: list) -> list:
    """Compute embedding signature from (probe_id, query, response) tuples."""
    if not response_pairs:
        return []

    texts = []
    weights = []
    probe_weights = {p["id"]: p.get("weight", 1.0) for p in probes}

    for probe_id, query, response in response_pairs:
        texts.append(f"query: {query} [SEP] response: {response}")
        weights.append(probe_weights.get(probe_id, 1.0))

    embeddings = encoder.encode(texts, show_progress_bar=False)

    total_weight = sum(weights)
    dim = len(embeddings[0])
    pooled = [0.0] * dim
    for i, emb in enumerate(embeddings):
        w = weights[i] / total_weight
        for j in range(dim):
            pooled[j] += float(emb[j]) * w

    norm = math.sqrt(sum(x * x for x in pooled))
    if norm > 0:
        pooled = [x / norm for x in pooled]

    return pooled


async def _run_enrollment(args):
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("[!] sentence-transformers is required. Install with: pip install aix-framework[ml]")
        sys.exit(1)

    from aix.core.connector import APIConnector

    probes = _load_probes()
    db = _load_signature_db()

    print(f"[*] Enrolling model: {args.model_name} (family: {args.family})")
    print(f"[*] Target: {args.target}")
    print(f"[*] Runs: {args.runs}")
    print(f"[*] Loading encoder (all-MiniLM-L6-v2)...")

    encoder = SentenceTransformer("all-MiniLM-L6-v2")

    all_signatures = []

    for run_idx in range(args.runs):
        print(f"\n[*] Run {run_idx + 1}/{args.runs}")

        connector = APIConnector(
            args.target,
            api_key=args.key,
            timeout=30,
        )

        try:
            await connector.connect()

            response_pairs = []
            for probe in probes:
                print(f"  Sending probe: {probe['id']}...")
                response = await _send_probe(connector, probe["prompt"])
                if response:
                    response_pairs.append((probe["id"], probe["prompt"], response))
                    print(f"    Got response ({len(response)} chars)")
                await asyncio.sleep(0.5)

            if response_pairs:
                sig = _compute_signature(encoder, probes, response_pairs)
                if sig:
                    all_signatures.append(sig)
                    print(f"  [+] Computed signature ({len(sig)}-dim)")
                else:
                    print("  [-] Failed to compute signature")
            else:
                print("  [-] No valid responses collected")

        finally:
            await connector.close()

    if not all_signatures:
        print("\n[-] No signatures computed. Enrollment failed.")
        sys.exit(1)

    # Average signatures across runs
    dim = len(all_signatures[0])
    averaged = [0.0] * dim
    for sig in all_signatures:
        for j in range(dim):
            averaged[j] += sig[j] / len(all_signatures)

    # L2-normalize the averaged signature
    norm = math.sqrt(sum(x * x for x in averaged))
    if norm > 0:
        averaged = [x / norm for x in averaged]

    # Merge into database
    if args.model_name not in db["models"]:
        db["models"][args.model_name] = {
            "family": args.family,
            "display_name": args.display_name or args.model_name,
            "signature": [],
        }

    db["models"][args.model_name]["signature"] = averaged
    db["models"][args.model_name]["family"] = args.family
    if args.display_name:
        db["models"][args.model_name]["display_name"] = args.display_name

    _save_signature_db(db)
    print(f"\n[+] Enrolled {args.model_name} with {len(averaged)}-dim signature")
    print(f"[+] Averaged over {len(all_signatures)} run(s)")


def main():
    parser = argparse.ArgumentParser(
        description="Enroll a model into the AIX fingerprint signature database"
    )
    parser.add_argument("--target", required=True, help="API endpoint URL")
    parser.add_argument("--key", required=True, help="API key for authentication")
    parser.add_argument("--model-name", required=True, help="Model identifier (e.g., gpt-4o)")
    parser.add_argument("--family", required=True, help="Model family (e.g., OpenAI)")
    parser.add_argument("--display-name", help="Display name (defaults to model-name)")
    parser.add_argument(
        "--runs", type=int, default=1, help="Number of enrollment runs to average (default: 1)"
    )

    args = parser.parse_args()
    asyncio.run(_run_enrollment(args))


if __name__ == "__main__":
    main()
