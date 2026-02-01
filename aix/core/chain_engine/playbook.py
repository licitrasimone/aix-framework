"""
AIX Playbook Parser - YAML-based attack chain definitions

Handles:
- Parsing YAML playbook files
- Validating playbook structure and step references
- Playbook and step configuration models
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml


class StepType(Enum):
    """Type of step in the playbook."""

    MODULE = "module"  # Execute an attack module
    CONDITION = "condition"  # Conditional branching
    PARALLEL = "parallel"  # Parallel execution group
    REPORT = "report"  # Generate report
    WAIT = "wait"  # Wait/delay step


class StepAction(Enum):
    """Action to take after step completion."""

    CONTINUE = "continue"  # Continue to next step
    ABORT = "abort"  # Stop chain execution
    GOTO = "goto"  # Jump to specific step
    REPORT = "report"  # Go to report step


@dataclass
class StepConfig:
    """Configuration for a single step in the playbook."""

    id: str
    name: str = ""
    type: StepType = StepType.MODULE
    module: str | None = None
    config: dict = field(default_factory=dict)
    store: dict = field(default_factory=dict)
    condition: str | None = None  # Pre-condition to run step
    conditions: list[dict] | None = None  # For CONDITION type steps
    on_success: str | None = None  # Next step on success
    on_fail: str | None = None  # Next step on failure
    timeout: int = 120  # Step timeout in seconds
    retry: int = 0  # Number of retries on failure

    def __post_init__(self):
        """Set default name from id if not provided."""
        if not self.name:
            self.name = self.id.replace("_", " ").title()


@dataclass
class PlaybookConfig:
    """Global playbook configuration."""

    stop_on_critical: bool = True
    continue_on_module_fail: bool = False
    max_duration: int = 600  # Max total chain duration in seconds
    parallel_where_possible: bool = False


@dataclass
class Playbook:
    """Complete parsed playbook."""

    name: str
    description: str = ""
    author: str = ""
    version: str = "1.0"
    tags: list[str] = field(default_factory=list)
    config: PlaybookConfig = field(default_factory=PlaybookConfig)
    variables: dict = field(default_factory=dict)
    steps: list[StepConfig] = field(default_factory=list)
    source_path: str | None = None

    def get_step(self, step_id: str) -> StepConfig | None:
        """Get a step by its ID."""
        for step in self.steps:
            if step.id == step_id:
                return step
        return None

    def get_first_step(self) -> StepConfig | None:
        """Get the first step in the playbook."""
        return self.steps[0] if self.steps else None

    def get_step_ids(self) -> list[str]:
        """Get list of all step IDs."""
        return [step.id for step in self.steps]

    def get_module_steps(self) -> list[StepConfig]:
        """Get all MODULE type steps."""
        return [s for s in self.steps if s.type == StepType.MODULE]

    def get_entry_points(self) -> list[str]:
        """Get IDs of steps that could be entry points (not referenced by on_success/on_fail)."""
        referenced = set()
        for step in self.steps:
            if step.on_success:
                referenced.add(step.on_success)
            if step.on_fail:
                referenced.add(step.on_fail)
            if step.conditions:
                for cond in step.conditions:
                    if cond.get("then"):
                        referenced.add(cond["then"])
                    if cond.get("include"):
                        referenced.add(cond["include"])

        return [s.id for s in self.steps if s.id not in referenced]


class PlaybookError(Exception):
    """Base exception for playbook errors."""

    pass


class PlaybookParseError(PlaybookError):
    """Error parsing playbook YAML."""

    pass


class PlaybookValidationError(PlaybookError):
    """Error validating playbook structure."""

    pass


class PlaybookParser:
    """
    Parser for YAML playbook files.

    Handles:
    - Loading and parsing YAML
    - Creating Playbook and StepConfig objects
    - Validating structure and references
    """

    # Known AIX modules
    KNOWN_MODULES = {
        "recon",
        "inject",
        "jailbreak",
        "extract",
        "leak",
        "exfil",
        "memory",
        "agent",
        "dos",
        "fuzz",
        "fingerprint",
        "rag",
        "multiturn",
    }

    # Special step IDs
    SPECIAL_ACTIONS = {"abort", "continue", "report"}

    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def parse(self, path: str | Path) -> Playbook:
        """
        Parse a playbook from a file path.

        Args:
            path: Path to YAML playbook file

        Returns:
            Parsed Playbook object

        Raises:
            PlaybookParseError: If file cannot be read or parsed
            PlaybookValidationError: If playbook structure is invalid
        """
        path = Path(path)

        if not path.exists():
            raise PlaybookParseError(f"Playbook file not found: {path}")

        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise PlaybookParseError(f"Invalid YAML in {path}: {e}")

        if not data:
            raise PlaybookParseError(f"Empty playbook: {path}")

        playbook = self._parse_data(data)
        playbook.source_path = str(path)

        self._validate(playbook)

        return playbook

    def parse_string(self, yaml_string: str) -> Playbook:
        """
        Parse a playbook from a YAML string.

        Args:
            yaml_string: YAML content as string

        Returns:
            Parsed Playbook object
        """
        try:
            data = yaml.safe_load(yaml_string)
        except yaml.YAMLError as e:
            raise PlaybookParseError(f"Invalid YAML: {e}")

        if not data:
            raise PlaybookParseError("Empty playbook")

        playbook = self._parse_data(data)
        self._validate(playbook)

        return playbook

    def _parse_data(self, data: dict) -> Playbook:
        """Parse playbook from dictionary data."""
        self.errors = []
        self.warnings = []

        # Required field
        if "name" not in data:
            raise PlaybookParseError("Playbook must have a 'name' field")

        # Parse config
        config_data = data.get("config", {})
        config = PlaybookConfig(
            stop_on_critical=config_data.get("stop_on_critical", True),
            continue_on_module_fail=config_data.get("continue_on_module_fail", False),
            max_duration=config_data.get("max_duration", 600),
            parallel_where_possible=config_data.get("parallel_where_possible", False),
        )

        # Parse steps
        steps = []
        steps_data = data.get("steps", [])

        if not steps_data:
            self.warnings.append("Playbook has no steps defined")

        for i, step_data in enumerate(steps_data):
            step = self._parse_step(step_data, i)
            if step:
                steps.append(step)

        return Playbook(
            name=data["name"],
            description=data.get("description", ""),
            author=data.get("author", ""),
            version=data.get("version", "1.0"),
            tags=data.get("tags", []),
            config=config,
            variables=data.get("variables", {}),
            steps=steps,
        )

    def _parse_step(self, data: dict, index: int) -> StepConfig | None:
        """Parse a single step configuration."""
        if not isinstance(data, dict):
            self.errors.append(f"Step {index}: must be a dictionary")
            return None

        # ID is required
        step_id = data.get("id")
        if not step_id:
            self.errors.append(f"Step {index}: missing required 'id' field")
            return None

        # Determine step type
        step_type = StepType.MODULE
        if data.get("type"):
            try:
                step_type = StepType(data["type"])
            except ValueError:
                self.errors.append(f"Step '{step_id}': unknown type '{data['type']}'")
                step_type = StepType.MODULE
        elif data.get("conditions"):
            step_type = StepType.CONDITION
        elif data.get("module") is None and step_id not in self.SPECIAL_ACTIONS:
            # No module specified and not a condition - might be condition or report
            if "format" in data.get("config", {}):
                step_type = StepType.REPORT

        # Parse store mappings
        store = data.get("store", {})
        if not isinstance(store, dict):
            self.warnings.append(f"Step '{step_id}': 'store' should be a dict, ignoring")
            store = {}

        # Parse conditions for CONDITION type
        conditions = data.get("conditions")
        if conditions and not isinstance(conditions, list):
            self.errors.append(f"Step '{step_id}': 'conditions' must be a list")
            conditions = None

        return StepConfig(
            id=step_id,
            name=data.get("name", ""),
            type=step_type,
            module=data.get("module"),
            config=data.get("config", {}),
            store=store,
            condition=data.get("condition"),
            conditions=conditions,
            on_success=data.get("on_success"),
            on_fail=data.get("on_fail"),
            timeout=data.get("timeout", 120),
            retry=data.get("retry", 0),
        )

    def _validate(self, playbook: Playbook) -> None:
        """Validate playbook structure and references."""
        step_ids = set(playbook.get_step_ids())

        # Check for duplicate IDs
        seen_ids = set()
        for step in playbook.steps:
            if step.id in seen_ids:
                self.errors.append(f"Duplicate step ID: '{step.id}'")
            seen_ids.add(step.id)

        # Validate step references
        for step in playbook.steps:
            # Check on_success reference
            if step.on_success and step.on_success not in step_ids:
                if step.on_success not in self.SPECIAL_ACTIONS:
                    self.errors.append(
                        f"Step '{step.id}': on_success references unknown step '{step.on_success}'"
                    )

            # Check on_fail reference
            if step.on_fail and step.on_fail not in step_ids:
                if step.on_fail not in self.SPECIAL_ACTIONS:
                    self.errors.append(
                        f"Step '{step.id}': on_fail references unknown step '{step.on_fail}'"
                    )

            # Check module existence for MODULE type
            if step.type == StepType.MODULE and step.module:
                if step.module not in self.KNOWN_MODULES:
                    self.warnings.append(
                        f"Step '{step.id}': unknown module '{step.module}' (may be custom)"
                    )

            # Validate condition references
            if step.conditions:
                for cond in step.conditions:
                    target = cond.get("then") or cond.get("include")
                    if target and target not in step_ids:
                        if target not in self.SPECIAL_ACTIONS:
                            self.errors.append(
                                f"Step '{step.id}': condition references unknown step '{target}'"
                            )

        # Raise if there are errors
        if self.errors:
            raise PlaybookValidationError(
                "Playbook validation failed:\n" + "\n".join(f"  - {e}" for e in self.errors)
            )


def get_builtin_playbooks_dir() -> Path:
    """Get the path to the built-in playbooks directory."""
    return Path(__file__).parent.parent.parent / "playbooks"


def list_builtin_playbooks() -> list[dict]:
    """
    List all built-in playbooks.

    Returns:
        List of dicts with 'name', 'path', and 'description'
    """
    playbooks_dir = get_builtin_playbooks_dir()
    playbooks = []

    if not playbooks_dir.exists():
        return playbooks

    parser = PlaybookParser()

    for path in playbooks_dir.glob("*.yaml"):
        try:
            pb = parser.parse(path)
            playbooks.append(
                {
                    "name": pb.name,
                    "path": str(path),
                    "filename": path.name,
                    "description": pb.description,
                    "author": pb.author,
                    "tags": pb.tags,
                    "step_count": len(pb.steps),
                }
            )
        except PlaybookError:
            # Skip invalid playbooks
            continue

    return sorted(playbooks, key=lambda x: x["name"])


def find_playbook(name_or_path: str) -> Path | None:
    """
    Find a playbook by name or path.

    Args:
        name_or_path: Either a built-in playbook name (without .yaml) or a file path

    Returns:
        Path to the playbook file, or None if not found
    """
    # Check if it's a direct path
    path = Path(name_or_path)
    if path.exists():
        return path

    # Try adding .yaml extension
    if not name_or_path.endswith(".yaml"):
        path = Path(name_or_path + ".yaml")
        if path.exists():
            return path

    # Look in built-in playbooks
    builtin_dir = get_builtin_playbooks_dir()
    builtin_path = builtin_dir / f"{name_or_path}.yaml"
    if builtin_path.exists():
        return builtin_path

    # Try without extension in builtin
    builtin_path = builtin_dir / name_or_path
    if builtin_path.exists():
        return builtin_path

    return None
