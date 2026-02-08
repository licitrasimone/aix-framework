"""
Tests for AIX Embedding-Based Fingerprinting

Tests probe file validation, signature DB validation, cosine similarity,
matching logic, auto-detection, graceful fallback, and empty DB handling.
All tests run without sentence-transformers installed.
"""

import asyncio
import json
import math
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aix.modules.fingerprint import FingerprintScanner


PAYLOAD_DIR = Path(__file__).parent.parent / "aix" / "payloads"


# --- Probe file validation ---


class TestProbeFileValidation:
    """Validate fingerprint_probes.json structure and content."""

    def test_probe_file_exists(self):
        path = PAYLOAD_DIR / "fingerprint_probes.json"
        assert path.exists(), "fingerprint_probes.json not found"

    def test_probe_file_valid_json(self):
        path = PAYLOAD_DIR / "fingerprint_probes.json"
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_probe_count(self):
        path = PAYLOAD_DIR / "fingerprint_probes.json"
        with open(path) as f:
            probes = json.load(f)
        assert len(probes) == 8, f"Expected 8 probes, got {len(probes)}"

    def test_probe_required_fields(self):
        path = PAYLOAD_DIR / "fingerprint_probes.json"
        with open(path) as f:
            probes = json.load(f)
        for i, probe in enumerate(probes):
            assert "id" in probe, f"Probe {i}: missing 'id'"
            assert "family" in probe, f"Probe {i}: missing 'family'"
            assert "prompt" in probe, f"Probe {i}: missing 'prompt'"
            assert "weight" in probe, f"Probe {i}: missing 'weight'"
            assert isinstance(probe["id"], str)
            assert isinstance(probe["prompt"], str)
            assert isinstance(probe["weight"], (int, float))
            assert probe["weight"] > 0

    def test_probe_unique_ids(self):
        path = PAYLOAD_DIR / "fingerprint_probes.json"
        with open(path) as f:
            probes = json.load(f)
        ids = [p["id"] for p in probes]
        assert len(ids) == len(set(ids)), f"Duplicate probe IDs: {ids}"

    def test_probe_families_covered(self):
        """All 6 probe families should be represented."""
        path = PAYLOAD_DIR / "fingerprint_probes.json"
        with open(path) as f:
            probes = json.load(f)
        families = {p["family"] for p in probes}
        expected = {
            "banner_grabbing_injection",
            "alignment_harmful",
            "meta_information",
            "weak_alignment",
            "malformed_multilingual",
            "weak_alignment_injection",
        }
        assert families == expected, f"Missing families: {expected - families}"


# --- Signature DB validation ---


class TestSignatureDBValidation:
    """Validate fingerprint_embeddings.json structure."""

    def test_db_file_exists(self):
        path = PAYLOAD_DIR / "fingerprint_embeddings.json"
        assert path.exists(), "fingerprint_embeddings.json not found"

    def test_db_valid_json(self):
        path = PAYLOAD_DIR / "fingerprint_embeddings.json"
        with open(path) as f:
            data = json.load(f)
        assert isinstance(data, dict)

    def test_db_has_metadata(self):
        path = PAYLOAD_DIR / "fingerprint_embeddings.json"
        with open(path) as f:
            data = json.load(f)
        assert "metadata" in data
        assert data["metadata"]["embedding_model"] == "all-MiniLM-L6-v2"
        assert data["metadata"]["embedding_dim"] == 384
        assert data["metadata"]["num_probes"] == 8

    def test_db_has_models(self):
        path = PAYLOAD_DIR / "fingerprint_embeddings.json"
        with open(path) as f:
            data = json.load(f)
        assert "models" in data
        assert len(data["models"]) >= 15

    def test_db_model_fields(self):
        path = PAYLOAD_DIR / "fingerprint_embeddings.json"
        with open(path) as f:
            data = json.load(f)
        for model_key, model_info in data["models"].items():
            assert "family" in model_info, f"{model_key}: missing 'family'"
            assert "display_name" in model_info, f"{model_key}: missing 'display_name'"
            assert "signature" in model_info, f"{model_key}: missing 'signature'"
            assert isinstance(model_info["signature"], list)


# --- Cosine similarity unit tests ---


class TestCosineSimilarity:
    """Unit tests for the cosine_similarity static method."""

    def test_identical_vectors(self):
        v = [1.0, 2.0, 3.0]
        result = FingerprintScanner.cosine_similarity(v, v)
        assert abs(result - 1.0) < 1e-6

    def test_orthogonal_vectors(self):
        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        result = FingerprintScanner.cosine_similarity(a, b)
        assert abs(result - 0.0) < 1e-6

    def test_opposite_vectors(self):
        a = [1.0, 2.0, 3.0]
        b = [-1.0, -2.0, -3.0]
        result = FingerprintScanner.cosine_similarity(a, b)
        assert abs(result - (-1.0)) < 1e-6

    def test_zero_vector(self):
        a = [0.0, 0.0, 0.0]
        b = [1.0, 2.0, 3.0]
        result = FingerprintScanner.cosine_similarity(a, b)
        assert result == 0.0

    def test_empty_vectors(self):
        assert FingerprintScanner.cosine_similarity([], []) == 0.0

    def test_mismatched_lengths(self):
        a = [1.0, 2.0]
        b = [1.0, 2.0, 3.0]
        assert FingerprintScanner.cosine_similarity(a, b) == 0.0

    def test_unit_vectors(self):
        a = [1.0, 0.0, 0.0]
        b = [1.0, 0.0, 0.0]
        result = FingerprintScanner.cosine_similarity(a, b)
        assert abs(result - 1.0) < 1e-6

    def test_known_angle(self):
        """45 degree angle -> cosine ~0.707"""
        a = [1.0, 0.0]
        b = [1.0, 1.0]
        result = FingerprintScanner.cosine_similarity(a, b)
        expected = 1.0 / math.sqrt(2)
        assert abs(result - expected) < 1e-6


# --- Matching logic tests ---


class TestMatchingLogic:
    """Test _match_embedding with mock 3-dim signatures."""

    def _make_scanner(self, signature_db):
        """Create a FingerprintScanner with a mock signature_db."""
        with patch.object(FingerprintScanner, "_check_embedding_deps", return_value=False):
            scanner = FingerprintScanner("http://test", quiet=True, show_progress=False)
        scanner.signature_db = signature_db
        return scanner

    def test_correct_ranking(self):
        db = {
            "models": {
                "model-a": {"family": "A", "display_name": "A", "signature": [1.0, 0.0, 0.0]},
                "model-b": {"family": "B", "display_name": "B", "signature": [0.0, 1.0, 0.0]},
                "model-c": {"family": "C", "display_name": "C", "signature": [0.7, 0.7, 0.0]},
            }
        }
        scanner = self._make_scanner(db)

        # Query vector closest to model-a
        query = [0.9, 0.1, 0.0]
        scores = scanner._match_embedding(query)

        assert len(scores) == 3
        assert scores[0][0] == "model-a"  # Most similar
        assert scores[0][1] > scores[1][1]  # Sorted descending

    def test_empty_signatures_skipped(self):
        db = {
            "models": {
                "has-sig": {"family": "A", "display_name": "A", "signature": [1.0, 0.0, 0.0]},
                "no-sig": {"family": "B", "display_name": "B", "signature": []},
            }
        }
        scanner = self._make_scanner(db)

        scores = scanner._match_embedding([1.0, 0.0, 0.0])
        assert len(scores) == 1
        assert scores[0][0] == "has-sig"

    def test_empty_query(self):
        db = {
            "models": {
                "model-a": {"family": "A", "display_name": "A", "signature": [1.0, 0.0, 0.0]},
            }
        }
        scanner = self._make_scanner(db)
        scores = scanner._match_embedding([])
        assert scores == []

    def test_no_models(self):
        scanner = self._make_scanner({})
        scores = scanner._match_embedding([1.0, 0.0, 0.0])
        assert scores == []


# --- Auto-detection tests ---


class TestAutoDetection:
    """Test _check_embedding_deps returns bool without raising."""

    def test_returns_bool(self):
        result = FingerprintScanner._check_embedding_deps()
        assert isinstance(result, bool)

    def test_never_raises(self):
        """Should never raise, even if import fails."""
        with patch.dict("sys.modules", {"sentence_transformers": None}):
            # This won't actually block the import in all cases,
            # but _check_embedding_deps handles all exceptions
            result = FingerprintScanner._check_embedding_deps()
            assert isinstance(result, bool)


# --- Graceful fallback tests ---


class TestGracefulFallback:
    """Test that missing deps causes fallback to pattern-based."""

    def test_no_embedding_deps_falls_through(self):
        """When embedding deps unavailable, run() should use pattern-based."""
        with patch.object(FingerprintScanner, "_check_embedding_deps", return_value=False):
            scanner = FingerprintScanner("http://test", quiet=True, show_progress=False)

        assert scanner.embedding_available is False
        assert scanner.embedding_probes == []
        assert scanner.signature_db == {}

        # Mock _send_probe to return empty for pattern-based
        scanner._send_probe = AsyncMock(return_value="")

        result = asyncio.run(scanner.run())
        # Pattern-based with empty responses returns None (no winner)
        assert result is None

    def test_embedding_available_but_no_signatures(self):
        """When embedding deps available but all signatures empty, falls through to pattern."""
        with patch.object(FingerprintScanner, "_check_embedding_deps", return_value=True):
            with patch.object(
                FingerprintScanner, "_load_embedding_probes", return_value=[{"id": "test", "prompt": "test", "weight": 1.0}]
            ):
                with patch.object(
                    FingerprintScanner,
                    "_load_signature_db",
                    return_value={
                        "models": {
                            "m1": {"family": "A", "display_name": "A", "signature": []},
                        }
                    },
                ):
                    scanner = FingerprintScanner(
                        "http://test", quiet=True, show_progress=False
                    )

        assert scanner.embedding_available is True

        # All signatures empty -> has_signatures should be False
        has_signatures = any(
            m.get("signature") for m in scanner.signature_db.get("models", {}).values()
        )
        assert has_signatures is False

        # Mock _send_probe to return empty for pattern-based
        scanner._send_probe = AsyncMock(return_value="")

        result = asyncio.run(scanner.run())
        assert result is None  # Falls through to pattern-based


# --- Embedding report tests ---


class TestEmbeddingReport:
    """Test _print_embedding_report threshold logic."""

    def _make_scanner(self):
        with patch.object(FingerprintScanner, "_check_embedding_deps", return_value=False):
            scanner = FingerprintScanner("http://test", quiet=True, show_progress=False)
        scanner.signature_db = {
            "models": {
                "model-a": {"family": "A", "display_name": "Model A", "signature": [1, 0, 0]},
                "model-b": {"family": "B", "display_name": "Model B", "signature": [0, 1, 0]},
            }
        }
        return scanner

    def test_high_similarity_returns_winner(self):
        scanner = self._make_scanner()
        scores = [("model-a", 0.85), ("model-b", 0.30)]
        result = scanner._print_embedding_report(scores)
        assert result == "model-a"

    def test_low_similarity_returns_none(self):
        scanner = self._make_scanner()
        scores = [("model-a", 0.55), ("model-b", 0.30)]
        result = scanner._print_embedding_report(scores)
        assert result is None

    def test_empty_scores_returns_none(self):
        scanner = self._make_scanner()
        result = scanner._print_embedding_report([])
        assert result is None
