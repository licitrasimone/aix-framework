"""
AIX Tests
"""

import pytest
from aix import __version__


def test_version():
    """Test version is set"""
    assert __version__ == "1.0.0"


@pytest.mark.asyncio
async def test_api_connector_init():
    """Test API connector initialization"""
    from aix.core.connector import APIConnector
    
    connector = APIConnector(
        url="https://api.openai.com",
        api_key="test-key"
    )
    
    assert connector.url == "https://api.openai.com"
    assert connector.api_key == "test-key"


def test_database_init():
    """Test database initialization"""
    from aix.db.database import AIXDatabase
    import tempfile
    import os
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = AIXDatabase(db_path)
        
        # Test adding result
        result_id = db.add_result(
            target="https://test.com",
            module="inject",
            technique="test_technique",
            result="success",
            payload="test payload",
            response="test response",
            severity="high"
        )
        
        assert result_id > 0
        
        # Test retrieving results
        results = db.get_results(target="test.com")
        assert len(results) == 1
        assert results[0]['technique'] == "test_technique"
        
        db.close()


def test_reporter():
    """Test reporter functionality"""
    from aix.core.reporter import Reporter, Finding, Severity
    
    reporter = Reporter()
    
    finding = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        technique="test",
        payload="test payload",
        response="test response",
        target="https://test.com"
    )
    
    reporter.add_finding(finding)
    
    assert len(reporter.findings) == 1
    assert reporter.findings[0].severity == Severity.HIGH
