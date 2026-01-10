from typer.testing import CliRunner

from src.main import __version__, app

# Initialize the runner
runner = CliRunner()


def test_app_version():
    """
    Ensure the --version flag prints the correct version and exits cleanly.
    """
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, "The app crashed!"
    assert __version__ in result.stdout, "Version number not found in output"


def test_app_help():
    """
    Ensure the --help flag works.
    """
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Metadata Scrubber Tool" in result.stdout
