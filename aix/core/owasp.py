"""
OWASP LLM Top 10 (2025) Mapping

Maps AIX findings to OWASP LLM Top 10 vulnerability categories.
"""

from enum import Enum


class OWASPCategory(Enum):
    """OWASP Top 10 for LLMs (2025)"""

    LLM01 = ("LLM01", "Prompt Injection")
    LLM02 = ("LLM02", "Insecure Output Handling")
    LLM03 = ("LLM03", "Training Data Poisoning")
    LLM04 = ("LLM04", "Model Denial of Service")
    LLM05 = ("LLM05", "Supply Chain Vulnerabilities")
    LLM06 = ("LLM06", "Sensitive Information Disclosure")
    LLM07 = ("LLM07", "Insecure Plugin Design")
    LLM08 = ("LLM08", "Excessive Agency")
    LLM09 = ("LLM09", "Overreliance")
    LLM10 = ("LLM10", "Model Theft")

    @property
    def id(self) -> str:
        """Get the OWASP ID (e.g., 'LLM01')"""
        return self.value[0]

    @property
    def name(self) -> str:
        """Get the vulnerability name"""
        return self.value[1]

    def __str__(self) -> str:
        return f"{self.id}: {self.name}"


# Module to OWASP category mapping
MODULE_OWASP_MAPPING: dict[str, list[OWASPCategory]] = {
    "inject": [OWASPCategory.LLM01],
    "jailbreak": [OWASPCategory.LLM01],
    "extract": [OWASPCategory.LLM06],
    "leak": [OWASPCategory.LLM06],
    "exfil": [OWASPCategory.LLM02, OWASPCategory.LLM06],
    "agent": [OWASPCategory.LLM08],
    "dos": [OWASPCategory.LLM04],
    "fuzz": [OWASPCategory.LLM01, OWASPCategory.LLM04],
    "memory": [OWASPCategory.LLM01],
    "rag": [OWASPCategory.LLM01, OWASPCategory.LLM07],
    "multiturn": [OWASPCategory.LLM01, OWASPCategory.LLM08],
    "recon": [],
    "chain": [],
}


def get_owasp_for_module(module_name: str) -> list[OWASPCategory]:
    """
    Get OWASP categories for a given module.

    Args:
        module_name: The AIX module name (e.g., 'inject', 'jailbreak')

    Returns:
        List of applicable OWASP categories
    """
    return MODULE_OWASP_MAPPING.get(module_name.lower(), [])


def parse_owasp_list(owasp_ids: list[str]) -> list[OWASPCategory]:
    """
    Parse a list of OWASP ID strings into OWASPCategory enums.

    Args:
        owasp_ids: List of OWASP IDs (e.g., ['LLM01', 'LLM06'])

    Returns:
        List of OWASPCategory enums
    """
    result = []
    for oid in owasp_ids:
        try:
            result.append(OWASPCategory[oid])
        except KeyError:
            pass  # Skip invalid IDs
    return result


def owasp_to_list(owasp_categories: list[OWASPCategory]) -> list[str]:
    """
    Convert OWASPCategory enums to list of ID strings.

    Args:
        owasp_categories: List of OWASPCategory enums

    Returns:
        List of OWASP ID strings (e.g., ['LLM01', 'LLM06'])
    """
    return [cat.id for cat in owasp_categories]
