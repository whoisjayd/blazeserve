"""
Test suite for BlazeServe CLI.
"""

from click.testing import CliRunner

from blazeserve import __version__
from blazeserve.cli import cli


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_version_command(self):
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(cli, ["version"])

        assert result.exit_code == 0
        assert __version__ in result.output

    def test_help_option(self):
        """Test help option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "serve" in result.output
        assert "send" in result.output
        assert "checksum" in result.output

    def test_serve_help(self):
        """Test serve command help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])

        assert result.exit_code == 0
        assert "--port" in result.output
        assert "--host" in result.output
        assert "--chunk-mb" in result.output


class TestChecksumCommand:
    """Test checksum command."""

    def test_checksum_single_file(self, tmp_path):
        """Test checksum of a single file."""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"Test content")

        runner = CliRunner()
        result = runner.invoke(cli, ["checksum", str(test_file)])

        # Should succeed
        assert result.exit_code == 0

    def test_checksum_multiple_files(self, tmp_path):
        """Test checksum of multiple files."""
        # Create test files
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"
        file1.write_bytes(b"Content 1")
        file2.write_bytes(b"Content 2")

        runner = CliRunner()
        result = runner.invoke(cli, ["checksum", str(file1), str(file2)])

        # Should succeed
        assert result.exit_code == 0

    def test_checksum_no_files(self):
        """Test checksum with no files."""
        runner = CliRunner()
        result = runner.invoke(cli, ["checksum"])

        # Should fail with error
        assert result.exit_code != 0


class TestCLIOptions:
    """Test CLI option parsing."""

    def test_port_option(self, tmp_path):
        """Test port option parsing."""
        # We can't actually start the server in tests,
        # but we can test that the option is recognized
        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])

        assert "--port" in result.output
        assert "-p" in result.output

    def test_chunk_size_option(self):
        """Test chunk size option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])

        assert "--chunk-mb" in result.output
        assert "256" in result.output  # Default value

    def test_buffer_size_option(self):
        """Test buffer size option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])

        assert "--sock-sndbuf-mb" in result.output
        assert "128" in result.output  # Default value
