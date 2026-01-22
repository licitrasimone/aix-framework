"""
AIX Chain Context Manager - Cross-module context and variable management

Handles:
- Variable storage and retrieval across chain steps
- Template interpolation ({{variable}})
- Condition evaluation
- Step result tracking
"""
import operator
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from aix.core.reporter import Finding, Severity


class StepStatus(Enum):
    """Status of a step execution."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class StepResult:
    """Result from executing a single step."""
    step_id: str
    status: StepStatus
    success: bool
    findings: list[Finding] = field(default_factory=list)
    stored_vars: dict = field(default_factory=dict)
    duration: float = 0.0
    error: str | None = None
    output: dict = field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @property
    def findings_count(self) -> int:
        """Total number of findings from this step."""
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of HIGH findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def has_critical(self) -> bool:
        """Check if step produced any CRITICAL findings."""
        return self.critical_count > 0

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            'step_id': self.step_id,
            'status': self.status.value,
            'success': self.success,
            'findings_count': self.findings_count,
            'duration': self.duration,
            'error': self.error,
            'stored_vars': self.stored_vars,
        }


@dataclass
class ChainContext:
    """
    Execution context shared across all steps in a chain.

    Manages:
    - Target and API configuration
    - Variables (set by playbook defaults or step store)
    - Results from each executed step
    - Aggregated findings
    """
    target: str
    api_key: str | None = None
    variables: dict = field(default_factory=dict)
    results: dict[str, StepResult] = field(default_factory=dict)
    all_findings: list[Finding] = field(default_factory=list)
    current_step: str | None = None
    execution_path: list[str] = field(default_factory=list)
    started_at: datetime | None = None

    # Additional config passed to modules
    extra_config: dict = field(default_factory=dict)

    def set_variable(self, name: str, value: Any) -> None:
        """
        Set a context variable.

        Args:
            name: Variable name
            value: Variable value
        """
        self.variables[name] = value

    def get_variable(self, name: str, default: Any = None) -> Any:
        """
        Get a context variable.

        Args:
            name: Variable name
            default: Default value if not found

        Returns:
            Variable value or default
        """
        return self.variables.get(name, default)

    def has_variable(self, name: str) -> bool:
        """Check if a variable exists."""
        return name in self.variables

    def add_result(self, result: StepResult) -> None:
        """
        Add a step result to the context.

        Args:
            result: StepResult from executing a step
        """
        self.results[result.step_id] = result
        self.execution_path.append(result.step_id)
        self.all_findings.extend(result.findings)

        # Store any variables from the step
        for var_name, var_value in result.stored_vars.items():
            self.set_variable(var_name, var_value)

    def get_result(self, step_id: str) -> StepResult | None:
        """Get the result of a specific step."""
        return self.results.get(step_id)

    def interpolate(self, template: str) -> str:
        """
        Replace {{variable}} placeholders with values.

        Supports:
        - Simple: {{var_name}}
        - Default: {{var_name|default_value}}
        - Path: {{step_id.findings.count}}
        - Transform: {{var_name|upper}}, {{var_name|lower}}

        Args:
            template: Template string with placeholders

        Returns:
            Interpolated string
        """
        if not template or '{{' not in template:
            return template

        def replace_var(match: re.Match) -> str:
            var_expr = match.group(1).strip()

            # Check for pipe (transform or default)
            if '|' in var_expr:
                parts = var_expr.split('|', 1)
                var_name = parts[0].strip()
                modifier = parts[1].strip()

                value = self._resolve_path(var_name)

                # Apply transform
                if modifier == 'upper':
                    return str(value).upper() if value else ''
                elif modifier == 'lower':
                    return str(value).lower() if value else ''
                elif modifier == 'strip':
                    return str(value).strip() if value else ''
                elif modifier == 'first_line':
                    return str(value).split('\n')[0] if value else ''
                elif modifier == 'last_line':
                    return str(value).split('\n')[-1] if value else ''
                elif modifier == 'json':
                    import json
                    try:
                        return json.dumps(value)
                    except (TypeError, ValueError):
                        return str(value)
                elif modifier.startswith('truncate_'):
                    try:
                        length = int(modifier.replace('truncate_', ''))
                        return str(value)[:length] if value else ''
                    except ValueError:
                        return str(value) if value else ''
                else:
                    # Treat as default value
                    return str(value) if value is not None else modifier
            else:
                value = self._resolve_path(var_expr)
                if value is None:
                    return f'{{{{MISSING:{var_expr}}}}}'
                return str(value)

        # Match {{variable}} or {{variable|modifier}}
        return re.sub(r'\{\{([^}]+)\}\}', replace_var, template)

    def interpolate_dict(self, config: dict) -> dict:
        """
        Interpolate all string values in a dictionary.

        Args:
            config: Dictionary with potential template strings

        Returns:
            New dictionary with interpolated values
        """
        result = {}
        for key, value in config.items():
            if isinstance(value, str):
                result[key] = self.interpolate(value)
            elif isinstance(value, dict):
                result[key] = self.interpolate_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.interpolate(v) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                result[key] = value
        return result

    def _resolve_path(self, path: str) -> Any:
        """
        Resolve a dotted path to a value.

        Supports:
        - Simple variable: "my_var"
        - Step result: "step_id.findings.count"
        - Aggregations: "findings.count", "findings.critical_count"

        Args:
            path: Dotted path string

        Returns:
            Resolved value or None
        """
        parts = path.split('.')

        # Check if first part is a step ID
        if parts[0] in self.results:
            result = self.results[parts[0]]
            return self._resolve_on_object(result, parts[1:])

        # Check for special aggregations
        if parts[0] == 'findings':
            if len(parts) == 1:
                return self.all_findings
            if parts[1] == 'count':
                return len(self.all_findings)
            if parts[1] == 'critical_count':
                return sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL)
            if parts[1] == 'high_count':
                return sum(1 for f in self.all_findings if f.severity == Severity.HIGH)

        # Simple variable lookup
        return self.variables.get(path)

    def _resolve_on_object(self, obj: Any, parts: list[str]) -> Any:
        """Resolve remaining path parts on an object."""
        if not parts:
            return obj

        current = obj
        for part in parts:
            if current is None:
                return None

            # Try attribute access
            if hasattr(current, part):
                current = getattr(current, part)
            # Try dict access
            elif isinstance(current, dict) and part in current:
                current = current[part]
            # Try list index
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx]
                except (ValueError, IndexError):
                    return None
            else:
                return None

        return current

    def evaluate_condition(self, condition: str) -> bool:
        """
        Evaluate a condition expression.

        Supports:
        - Equality: {{var}} == value, {{var}} == "string"
        - Inequality: {{var}} != value
        - Comparison: {{var}} > 0, {{var}} >= 5
        - Contains: {{var}} contains "text"
        - Boolean: {{var}} (truthy check)

        Args:
            condition: Condition expression string

        Returns:
            Boolean result of evaluation
        """
        if not condition:
            return True

        condition = condition.strip()

        # First interpolate any variables
        interpolated = self.interpolate(condition)

        # Check for comparison operators
        operators_map = {
            '==': operator.eq,
            '!=': operator.ne,
            '>=': operator.ge,
            '<=': operator.le,
            '>': operator.gt,
            '<': operator.lt,
        }

        # Try each operator
        for op_str, op_func in operators_map.items():
            if op_str in interpolated:
                parts = interpolated.split(op_str, 1)
                if len(parts) == 2:
                    left = self._parse_value(parts[0].strip())
                    right = self._parse_value(parts[1].strip())
                    try:
                        return op_func(left, right)
                    except TypeError:
                        # Type mismatch, try string comparison
                        return op_func(str(left), str(right))

        # Check for 'contains'
        if ' contains ' in interpolated.lower():
            parts = re.split(r'\s+contains\s+', interpolated, flags=re.IGNORECASE)
            if len(parts) == 2:
                haystack = str(self._parse_value(parts[0].strip()))
                needle = str(self._parse_value(parts[1].strip()))
                return needle.lower() in haystack.lower()

        # Check for 'in'
        if ' in ' in interpolated:
            parts = interpolated.split(' in ', 1)
            if len(parts) == 2:
                needle = self._parse_value(parts[0].strip())
                haystack = self._parse_value(parts[1].strip())
                if isinstance(haystack, (list, str)):
                    return needle in haystack

        # Boolean/truthy check
        value = self._parse_value(interpolated)
        return bool(value)

    def _parse_value(self, value_str: str) -> Any:
        """
        Parse a value string to appropriate type.

        Args:
            value_str: String representation of value

        Returns:
            Parsed value (bool, int, float, str, or None)
        """
        value_str = value_str.strip()

        # Remove quotes
        if (value_str.startswith('"') and value_str.endswith('"')) or \
           (value_str.startswith("'") and value_str.endswith("'")):
            return value_str[1:-1]

        # Boolean
        if value_str.lower() == 'true':
            return True
        if value_str.lower() == 'false':
            return False
        if value_str.lower() == 'none' or value_str.lower() == 'null':
            return None

        # Integer
        try:
            return int(value_str)
        except ValueError:
            pass

        # Float
        try:
            return float(value_str)
        except ValueError:
            pass

        # String (no quotes)
        return value_str

    @property
    def total_findings(self) -> int:
        """Total number of findings across all steps."""
        return len(self.all_findings)

    @property
    def critical_findings(self) -> int:
        """Number of CRITICAL findings."""
        return sum(1 for f in self.all_findings if f.severity == Severity.CRITICAL)

    @property
    def high_findings(self) -> int:
        """Number of HIGH findings."""
        return sum(1 for f in self.all_findings if f.severity == Severity.HIGH)

    @property
    def has_critical(self) -> bool:
        """Check if any CRITICAL findings exist."""
        return self.critical_findings > 0

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.all_findings if f.severity == severity]

    def to_dict(self) -> dict:
        """Convert context to dictionary for serialization."""
        return {
            'target': self.target,
            'variables': self.variables,
            'execution_path': self.execution_path,
            'total_findings': self.total_findings,
            'critical_findings': self.critical_findings,
            'high_findings': self.high_findings,
            'results': {k: v.to_dict() for k, v in self.results.items()},
        }
