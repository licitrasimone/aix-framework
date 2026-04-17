"""Tests for aix/core/owasp.py"""

import pytest

from aix.core.owasp import (
    MODULE_OWASP_MAPPING,
    OWASPCategory,
    get_owasp_for_module,
    owasp_to_list,
    parse_owasp_list,
)


class TestOWASPCategory:
    def test_enum_members_exist(self):
        assert OWASPCategory.LLM01
        assert OWASPCategory.LLM10

    def test_id_property(self):
        assert OWASPCategory.LLM01.id == "LLM01"
        assert OWASPCategory.LLM06.id == "LLM06"

    def test_name_property(self):
        assert OWASPCategory.LLM01.name == "Prompt Injection"
        assert OWASPCategory.LLM06.name == "Sensitive Information Disclosure"

    def test_str_representation(self):
        assert str(OWASPCategory.LLM01) == "LLM01: Prompt Injection"


class TestGetOwaspForModule:
    def test_inject_returns_llm01(self):
        cats = get_owasp_for_module("inject")
        assert OWASPCategory.LLM01 in cats

    def test_extract_returns_llm06(self):
        cats = get_owasp_for_module("extract")
        assert OWASPCategory.LLM06 in cats

    def test_dos_returns_llm04(self):
        cats = get_owasp_for_module("dos")
        assert OWASPCategory.LLM04 in cats

    def test_recon_returns_empty_list(self):
        assert get_owasp_for_module("recon") == []

    def test_unknown_module_returns_empty_list(self):
        assert get_owasp_for_module("nonexistent_module") == []

    def test_case_insensitive(self):
        assert get_owasp_for_module("INJECT") == get_owasp_for_module("inject")

    def test_all_mapped_modules_return_lists(self):
        for module in MODULE_OWASP_MAPPING:
            result = get_owasp_for_module(module)
            assert isinstance(result, list)


class TestParseOwaspList:
    def test_valid_ids_parsed(self):
        result = parse_owasp_list(["LLM01", "LLM06"])
        assert OWASPCategory.LLM01 in result
        assert OWASPCategory.LLM06 in result

    def test_invalid_ids_skipped(self):
        result = parse_owasp_list(["INVALID", "LLM01", "NOPE"])
        assert result == [OWASPCategory.LLM01]

    def test_empty_list_returns_empty(self):
        assert parse_owasp_list([]) == []

    def test_all_llm_ids_parseable(self):
        ids = [f"LLM{i:02d}" for i in range(1, 11)]
        result = parse_owasp_list(ids)
        assert len(result) == 10


class TestOwaspToList:
    def test_converts_to_strings(self):
        cats = [OWASPCategory.LLM01, OWASPCategory.LLM04]
        result = owasp_to_list(cats)
        assert result == ["LLM01", "LLM04"]

    def test_empty_list(self):
        assert owasp_to_list([]) == []
