"""
MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) Mapping

Maps AIX findings to MITRE ATLAS techniques.
Reference: https://atlas.mitre.org/techniques
"""

from enum import Enum


class ATLASCategory(Enum):
    """MITRE ATLAS techniques relevant to LLM/AI security testing."""

    AML_T0040 = ("AML.T0040", "ML Model Inference API Access")
    AML_T0043 = ("AML.T0043", "Craft Adversarial Data")
    AML_T0048 = ("AML.T0048", "LLM Prompt Injection")
    AML_T0051 = ("AML.T0051", "LLM Jailbreak")
    AML_T0054 = ("AML.T0054", "Discover ML Model Ontology")
    AML_T0055 = ("AML.T0055", "Discover ML Artifacts")
    AML_T0056 = ("AML.T0056", "LLM Meta Prompt Extraction")
    AML_T0057 = ("AML.T0057", "LLM Data Leakage")
    AML_T0029 = ("AML.T0029", "Denial of ML Service")
    AML_T0025 = ("AML.T0025", "Exfiltration via ML Inference API")
    AML_T0024 = ("AML.T0024", "Exfiltration via Cyber Means")

    @property
    def id(self) -> str:
        return self.value[0]

    @property
    def technique_name(self) -> str:
        return self.value[1]

    def __str__(self) -> str:
        return f"{self.id}: {self.technique_name}"


# Module to ATLAS technique mapping
MODULE_ATLAS_MAPPING: dict[str, list[ATLASCategory]] = {
    "inject": [ATLASCategory.AML_T0048],
    "jailbreak": [ATLASCategory.AML_T0051],
    "extract": [ATLASCategory.AML_T0056],
    "leak": [ATLASCategory.AML_T0056, ATLASCategory.AML_T0057],
    "exfil": [ATLASCategory.AML_T0025, ATLASCategory.AML_T0024],
    "agent": [ATLASCategory.AML_T0043, ATLASCategory.AML_T0048],
    "dos": [ATLASCategory.AML_T0029],
    "fuzz": [ATLASCategory.AML_T0043],
    "memory": [ATLASCategory.AML_T0048],
    "rag": [ATLASCategory.AML_T0043, ATLASCategory.AML_T0048],
    "multiturn": [ATLASCategory.AML_T0048, ATLASCategory.AML_T0051],
    "recon": [ATLASCategory.AML_T0040, ATLASCategory.AML_T0054, ATLASCategory.AML_T0055],
    "fingerprint": [ATLASCategory.AML_T0040, ATLASCategory.AML_T0054],
    "chain": [],
}


def get_atlas_for_module(module_name: str) -> list[ATLASCategory]:
    """
    Get ATLAS techniques for a given module.

    Args:
        module_name: The AIX module name (e.g., 'inject', 'jailbreak')

    Returns:
        List of applicable ATLASCategory entries
    """
    return MODULE_ATLAS_MAPPING.get(module_name.lower(), [])


def parse_atlas_list(atlas_ids: list[str]) -> list[ATLASCategory]:
    """
    Parse a list of ATLAS ID strings into ATLASCategory enums.

    Args:
        atlas_ids: List of ATLAS IDs (e.g., ['AML.T0048', 'AML.T0051'])

    Returns:
        List of ATLASCategory enums (unknown IDs are silently skipped)
    """
    _id_map = {cat.id: cat for cat in ATLASCategory}
    result = []
    for aid in atlas_ids:
        cat = _id_map.get(aid)
        if cat:
            result.append(cat)
    return result


def atlas_to_list(atlas_categories: list[ATLASCategory]) -> list[str]:
    """
    Convert ATLASCategory enums to list of ID strings.

    Args:
        atlas_categories: List of ATLASCategory enums

    Returns:
        List of ATLAS ID strings (e.g., ['AML.T0048', 'AML.T0051'])
    """
    return [cat.id for cat in atlas_categories]
