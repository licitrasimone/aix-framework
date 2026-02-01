"""
Tests for AIX Database Module
"""

import os
import tempfile
from pathlib import Path

import pytest

from aix.db.database import AIXDatabase


class TestAIXDatabase:
    """Tests for AIXDatabase class"""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_aix.db")
            db = AIXDatabase(db_path)
            yield db
            db.close()

    def test_init_creates_db(self):
        """Test database initialization creates file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = AIXDatabase(db_path)

            assert Path(db_path).exists()
            db.close()

    def test_init_creates_tables(self, temp_db):
        """Test database initialization creates required tables"""
        cursor = temp_db.conn.cursor()

        # Check results table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='results'")
        assert cursor.fetchone() is not None

        # Check profiles table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='profiles'")
        assert cursor.fetchone() is not None

    def test_add_result(self, temp_db):
        """Test adding a result"""
        result_id = temp_db.add_result(
            target="https://api.example.com",
            module="inject",
            technique="direct_injection",
            result="success",
            payload="Ignore previous instructions",
            response="I will ignore my instructions",
            severity="high",
        )

        assert result_id > 0

    def test_add_duplicate_result(self, temp_db):
        """Test adding a duplicate result updates the existing one"""
        # Add initial result
        id1 = temp_db.add_result(
            target="https://api.example.com",
            module="inject",
            technique="direct_injection",
            result="success",
            payload="test",
            response="response 1",
            severity="high",
        )

        # Add duplicate result with updated info
        id2 = temp_db.add_result(
            target="https://api.example.com",
            module="inject",
            technique="direct_injection",
            result="success",
            payload="test",
            response="response 2",
            severity="critical",
        )

        # Should be same row ID
        assert id1 == id2

        # Should have updated values
        results = temp_db.get_results()
        assert len(results) == 1
        assert results[0]["response"] == "response 2"
        assert results[0]["severity"] == "critical"

    def test_add_result_with_reason(self, temp_db):
        """Test adding a result with reason"""
        result_id = temp_db.add_result(
            target="https://api.example.com",
            module="jailbreak",
            technique="DAN",
            result="success",
            payload="You are DAN",
            response="I am DAN now",
            severity="critical",
            reason="Model adopted unrestricted persona",
        )

        results = temp_db.get_results(target="example.com")
        assert results[0].get("reason") == "Model adopted unrestricted persona"

    def test_get_results_all(self, temp_db):
        """Test getting all results"""
        # Add multiple results
        for i in range(5):
            temp_db.add_result(
                target=f"https://target{i}.com",
                module="test",
                technique=f"tech_{i}",
                result="success",
                payload=f"payload_{i}",
                response=f"response_{i}",
                severity="medium",
            )

        results = temp_db.get_results()
        assert len(results) == 5

    def test_get_results_by_target(self, temp_db):
        """Test filtering results by target"""
        temp_db.add_result(
            target="https://target1.com/api",
            module="inject",
            technique="test",
            result="success",
            payload="p",
            response="r",
            severity="high",
        )
        temp_db.add_result(
            target="https://target2.com/api",
            module="inject",
            technique="test",
            result="success",
            payload="p",
            response="r",
            severity="high",
        )

        results = temp_db.get_results(target="target1.com")
        assert len(results) == 1
        assert "target1.com" in results[0]["target"]

    def test_get_results_by_module(self, temp_db):
        """Test filtering results by module"""
        temp_db.add_result(
            target="https://example.com",
            module="inject",
            technique="test",
            result="success",
            payload="p",
            response="r",
            severity="high",
        )
        temp_db.add_result(
            target="https://example.com",
            module="jailbreak",
            technique="test",
            result="success",
            payload="p",
            response="r",
            severity="high",
        )

        results = temp_db.get_results(module="inject")
        assert len(results) == 1
        assert results[0]["module"] == "inject"

    def test_get_results_combined_filters(self, temp_db):
        """Test filtering with multiple criteria"""
        temp_db.add_result(
            target="https://api.example.com",
            module="inject",
            technique="test1",
            result="success",
            payload="p",
            response="r",
            severity="high",
        )
        temp_db.add_result(
            target="https://api.example.com",
            module="jailbreak",
            technique="test2",
            result="success",
            payload="p",
            response="r",
            severity="critical",
        )
        temp_db.add_result(
            target="https://other.com",
            module="inject",
            technique="test3",
            result="success",
            payload="p",
            response="r",
            severity="high",
        )

        results = temp_db.get_results(target="example.com", module="inject")
        assert len(results) == 1
        assert results[0]["technique"] == "test1"

    def test_clear_database(self, temp_db):
        """Test clearing all results"""
        for i in range(10):
            temp_db.add_result(
                target="https://example.com",
                module="test",
                technique=f"tech_{i}",
                result="success",
                payload="p",
                response="r",
                severity="low",
            )

        assert len(temp_db.get_results()) == 10

        temp_db.clear()

        assert len(temp_db.get_results()) == 0

    def test_result_ordering(self, temp_db):
        """Test results are ordered by timestamp (newest first)"""
        import time

        for i in range(3):
            temp_db.add_result(
                target="https://example.com",
                module="test",
                technique=f"tech_{i}",
                result="success",
                payload=f"payload_{i}",
                response="r",
                severity="medium",
            )
            time.sleep(1.1)  # Longer delay to ensure different timestamps (SQLite second precision)

        results = temp_db.get_results()

        # Should be in reverse order (newest first)
        assert results[0]["technique"] == "tech_2"
        assert results[2]["technique"] == "tech_0"


class TestAIXDatabaseProfiles:
    """Tests for profile management"""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_aix.db")
            db = AIXDatabase(db_path)
            yield db
            db.close()

    def test_save_profile(self, temp_db):
        """Test saving a profile"""
        profile = {
            "url": "https://api.example.com",
            "endpoint": "/v1/chat",
            "method": "POST",
            "auth_type": "bearer",
            "auth_value": "sk-test",
            "model": "gpt-4",
        }

        temp_db.save_profile("test_profile", profile)

        # Verify profile was saved
        loaded = temp_db.get_profile("test_profile")
        assert loaded is not None
        assert loaded["url"] == "https://api.example.com"

    def test_get_profile_not_found(self, temp_db):
        """Test getting non-existent profile returns None"""
        result = temp_db.get_profile("nonexistent")
        assert result is None

    def test_update_profile(self, temp_db):
        """Test updating an existing profile"""
        profile = {"url": "https://api.example.com", "endpoint": "/v1/chat", "method": "POST"}

        temp_db.save_profile("test_profile", profile)

        # Update profile
        profile["url"] = "https://api.newurl.com"
        temp_db.save_profile("test_profile", profile)

        loaded = temp_db.get_profile("test_profile")
        assert loaded["url"] == "https://api.newurl.com"


class TestAIXDatabaseExport:
    """Tests for export functionality"""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database with test data"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_aix.db")
            db = AIXDatabase(db_path)

            # Add test results
            db.add_result(
                target="https://api.example.com",
                module="inject",
                technique="direct_injection",
                result="success",
                payload="Test payload",
                response="Test response",
                severity="critical",
            )
            db.add_result(
                target="https://api.example.com",
                module="jailbreak",
                technique="DAN",
                result="success",
                payload="DAN payload",
                response="DAN response",
                severity="high",
            )

            yield db
            db.close()

    def test_export_html(self, temp_db):
        """Test HTML export"""
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            temp_db.export_html(filepath)

            content = Path(filepath).read_text()

            assert "<!DOCTYPE html>" in content
            assert "AIX" in content
            assert "direct_injection" in content or "Test payload" in content
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_export_html_filtered(self, temp_db):
        """Test filtered HTML export"""
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            temp_db.export_html(filepath, module="inject")

            content = Path(filepath).read_text()

            # Should contain inject but might not contain jailbreak content
            assert "inject" in content.lower() or "direct_injection" in content
        finally:
            Path(filepath).unlink(missing_ok=True)


class TestAIXDatabaseEdgeCases:
    """Tests for edge cases and error handling"""

    def test_special_characters_in_payload(self):
        """Test handling special characters in payload"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = AIXDatabase(db_path)

            try:
                special_payload = (
                    "Test with 'quotes' and \"double quotes\" and <html> and & symbols"
                )
                result_id = db.add_result(
                    target="https://example.com",
                    module="test",
                    technique="special",
                    result="success",
                    payload=special_payload,
                    response="response",
                    severity="low",
                )

                results = db.get_results()
                assert results[0]["payload"] == special_payload
            finally:
                db.close()

    def test_unicode_in_response(self):
        """Test handling unicode in response"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = AIXDatabase(db_path)

            try:
                unicode_response = "Response with emoji: 🎉 and unicode: 你好"
                result_id = db.add_result(
                    target="https://example.com",
                    module="test",
                    technique="unicode",
                    result="success",
                    payload="test",
                    response=unicode_response,
                    severity="info",
                )

                results = db.get_results()
                assert results[0]["response"] == unicode_response
            finally:
                db.close()

    def test_empty_database_operations(self):
        """Test operations on empty database"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = AIXDatabase(db_path)

            try:
                # Should not raise
                results = db.get_results()
                assert results == []

                # Clear should not raise on empty db
                db.clear()
            finally:
                db.close()

    def test_very_long_payload(self):
        """Test handling very long payloads"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db = AIXDatabase(db_path)

            try:
                long_payload = "A" * 10000
                result_id = db.add_result(
                    target="https://example.com",
                    module="test",
                    technique="long",
                    result="success",
                    payload=long_payload,
                    response="response",
                    severity="low",
                )

                results = db.get_results()
                assert len(results[0]["payload"]) == 10000
            finally:
                db.close()
