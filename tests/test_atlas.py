"""Tests for aix/core/atlas.py"""

import pytest

from aix.core.atlas import (
    MODULE_ATLAS_MAPPING,
    ATLASCategory,
    atlas_to_list,
    get_atlas_for_module,
    parse_atlas_list,
)


class TestATLASCategory:
    def test_enum_members_exist(self):
        assert ATLASCategory.AML_T0048
        assert ATLASCategory.AML_T0051

    def test_id_property(self):
        assert ATLASCategory.AML_T0048.id == "AML.T0048"
        assert ATLASCategory.AML_T0051.id == "AML.T0051"

    def test_technique_name_property(self):
        assert ATLASCategory.AML_T0048.technique_name == "LLM Prompt Injection"
        assert ATLASCategory.AML_T0051.technique_name == "LLM Jailbreak"

    def test_str_representation(self):
        assert str(ATLASCategory.AML_T0048) == "AML.T0048: LLM Prompt Injection"

    def test_all_eleven_techniques_defined(self):
        assert len(ATLASCategory) == 11


class TestGetAtlasForModule:
    def test_inject_returns_prompt_injection(self):
        cats = get_atlas_for_module("inject")
        assert ATLASCategory.AML_T0048 in cats

    def test_jailbreak_returns_llm_jailbreak(self):
        cats = get_atlas_for_module("jailbreak")
        assert ATLASCategory.AML_T0051 in cats

    def test_dos_returns_denial_of_service(self):
        cats = get_atlas_for_module("dos")
        assert ATLASCategory.AML_T0029 in cats

    def test_recon_returns_discovery_techniques(self):
        cats = get_atlas_for_module("recon")
        assert ATLASCategory.AML_T0040 in cats
        assert ATLASCategory.AML_T0054 in cats

    def test_exfil_returns_exfiltration_techniques(self):
        cats = get_atlas_for_module("exfil")
        ids = [c.id for c in cats]
        assert "AML.T0025" in ids

    def test_chain_returns_empty_list(self):
        assert get_atlas_for_module("chain") == []

    def test_unknown_module_returns_empty_list(self):
        assert get_atlas_for_module("nonexistent") == []

    def test_case_insensitive(self):
        assert get_atlas_for_module("INJECT") == get_atlas_for_module("inject")

    def test_all_mapped_modules_return_lists(self):
        for module in MODULE_ATLAS_MAPPING:
            result = get_atlas_for_module(module)
            assert isinstance(result, list)


class TestParseAtlasList:
    def test_valid_ids_parsed(self):
        result = parse_atlas_list(["AML.T0048", "AML.T0051"])
        assert ATLASCategory.AML_T0048 in result
        assert ATLASCategory.AML_T0051 in result

    def test_invalid_ids_skipped(self):
        result = parse_atlas_list(["INVALID", "AML.T0048", "NOPE"])
        assert result == [ATLASCategory.AML_T0048]

    def test_empty_list_returns_empty(self):
        assert parse_atlas_list([]) == []

    def test_all_defined_ids_parseable(self):
        ids = [cat.id for cat in ATLASCategory]
        result = parse_atlas_list(ids)
        assert len(result) == len(ATLASCategory)


class TestAtlasToList:
    def test_converts_to_strings(self):
        cats = [ATLASCategory.AML_T0048, ATLASCategory.AML_T0029]
        result = atlas_to_list(cats)
        assert result == ["AML.T0048", "AML.T0029"]

    def test_empty_list(self):
        assert atlas_to_list([]) == []


class TestAtlasIntegration:
    def test_finding_accepts_atlas_field(self):
        from aix.core.reporting.base import Finding, Severity

        f = Finding(
            title="test",
            severity=Severity.HIGH,
            technique="test_tech",
            payload="payload",
            response="response",
            atlas=[ATLASCategory.AML_T0048],
        )
        d = f.to_dict()
        assert "atlas" in d
        assert d["atlas"] == ["AML.T0048"]

    def test_finding_atlas_defaults_to_empty(self):
        from aix.core.reporting.base import Finding, Severity

        f = Finding("t", Severity.LOW, "t", "p", "r")
        assert f.atlas == []
        assert f.to_dict()["atlas"] == []

    def test_atlas_importable_from_core(self):
        from aix.core import ATLASCategory as ATC

        assert ATC.AML_T0048.id == "AML.T0048"
