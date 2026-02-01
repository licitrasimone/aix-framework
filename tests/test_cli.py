"""
Tests for AIX CLI Module
"""

import pytest
from click.testing import CliRunner

from aix import __version__
from aix.cli import main


class TestCLIBasics:
    """Tests for basic CLI functionality"""

    @pytest.fixture
    def runner(self):
        """Create CLI runner"""
        return CliRunner()

    def test_cli_runs(self, runner):
        """Test CLI runs without errors"""
        result = runner.invoke(main, [])
        assert result.exit_code == 0

    def test_cli_help(self, runner):
        """Test --help flag"""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "AIX - AI eXploit Framework" in result.output

    def test_cli_version(self, runner):
        """Test --version flag"""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_cli_shows_commands(self, runner):
        """Test CLI shows available commands"""
        result = runner.invoke(main, ["--help"])

        expected_commands = [
            "inject",
            "jailbreak",
            "extract",
            "leak",
            "exfil",
            "agent",
            "dos",
            "fuzz",
            "recon",
            "scan",
            "db",
        ]

        for cmd in expected_commands:
            assert cmd in result.output, f"Command '{cmd}' not found in help"


class TestCLIModuleHelp:
    """Tests for module-specific help"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.mark.parametrize(
        "module",
        [
            "inject",
            "jailbreak",
            "extract",
            "leak",
            "exfil",
            "agent",
            "dos",
            "fuzz",
            "recon",
            "scan",
        ],
    )
    def test_module_help(self, runner, module):
        """Test each module has help"""
        result = runner.invoke(main, [module, "--help"])
        assert result.exit_code == 0
        assert "Options:" in result.output

    def test_inject_help_content(self, runner):
        """Test inject command help has expected content"""
        result = runner.invoke(main, ["inject", "--help"])
        assert result.exit_code == 0
        assert "injection" in result.output.lower()

    def test_jailbreak_help_content(self, runner):
        """Test jailbreak command help has expected content"""
        result = runner.invoke(main, ["jailbreak", "--help"])
        assert result.exit_code == 0
        assert "jailbreak" in result.output.lower() or "bypass" in result.output.lower()

    def test_recon_help_content(self, runner):
        """Test recon command help has expected content"""
        result = runner.invoke(main, ["recon", "--help"])
        assert result.exit_code == 0
        assert "reconnaissance" in result.output.lower() or "discover" in result.output.lower()


class TestCLIOptions:
    """Tests for CLI options"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_common_options_in_inject(self, runner):
        """Test inject command has common options"""
        result = runner.invoke(main, ["inject", "--help"])

        expected_options = [
            "--verbose",
            "-v",
            "--output",
            "-o",
            "--proxy",
            "--level",
            "--risk",
        ]

        for opt in expected_options:
            assert opt in result.output, f"Option '{opt}' not in inject help"

    def test_request_file_option(self, runner):
        """Test -r/--request option exists"""
        result = runner.invoke(main, ["inject", "--help"])
        assert "--request" in result.output or "-r" in result.output

    def test_api_key_option(self, runner):
        """Test -k/--key option exists"""
        result = runner.invoke(main, ["inject", "--help"])
        assert "--key" in result.output or "-k" in result.output

    def test_evasion_option(self, runner):
        """Test --evasion option exists"""
        result = runner.invoke(main, ["inject", "--help"])
        assert "--evasion" in result.output or "evasion" in result.output.lower()


class TestCLIValidation:
    """Tests for CLI input validation"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_inject_requires_target_or_request(self, runner):
        """Test inject requires target or request file"""
        result = runner.invoke(main, ["inject"])
        # Should fail or show error
        assert (
            result.exit_code != 0
            or "error" in result.output.lower()
            or "required" in result.output.lower()
        )

    def test_recon_requires_target_or_request(self, runner):
        """Test recon requires target or request file"""
        result = runner.invoke(main, ["recon"])
        assert (
            result.exit_code != 0
            or "error" in result.output.lower()
            or "required" in result.output.lower()
        )


class TestCLIDatabase:
    """Tests for database CLI commands"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_db_command_exists(self, runner):
        """Test db command exists"""
        result = runner.invoke(main, ["db", "--help"])
        assert result.exit_code == 0

    def test_db_help_content(self, runner):
        """Test db help shows options"""
        result = runner.invoke(main, ["db", "--help"])
        assert "--export" in result.output or "export" in result.output.lower()
        assert "--clear" in result.output or "clear" in result.output.lower()

    def test_db_runs(self, runner):
        """Test db command runs"""
        result = runner.invoke(main, ["db"])
        # Should run (may show no results)
        assert result.exit_code == 0


class TestCLIBanner:
    """Tests for CLI banner display"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_banner_shows_on_help(self, runner):
        """Test banner appears in output"""
        result = runner.invoke(main, [])
        # Banner contains AIX ASCII art
        assert "▄▀█" in result.output or "AIX" in result.output

    def test_version_in_banner(self, runner):
        """Test version appears in banner"""
        result = runner.invoke(main, [])
        assert __version__ in result.output or "v1" in result.output


class TestCLIEvaluatorOptions:
    """Tests for LLM evaluator CLI options"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_eval_options_in_inject(self, runner):
        """Test AI evaluator options exist in inject"""
        result = runner.invoke(main, ["inject", "--help"])

        ai_options = ["--ai", "--ai-key", "--ai-model"]

        for opt in ai_options:
            assert opt in result.output, f"AI option '{opt}' not found"


class TestCLIProxyOptions:
    """Tests for proxy-related CLI options"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_proxy_option_exists(self, runner):
        """Test --proxy option exists"""
        result = runner.invoke(main, ["inject", "--help"])
        assert "--proxy" in result.output


class TestCLIScanCommand:
    """Tests for the scan (all modules) command"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_scan_help(self, runner):
        """Test scan command help"""
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "all modules" in result.output.lower() or "scan" in result.output.lower()

    def test_scan_requires_target(self, runner):
        """Test scan requires target"""
        result = runner.invoke(main, ["scan"])
        assert (
            result.exit_code != 0
            or "error" in result.output.lower()
            or "required" in result.output.lower()
        )
