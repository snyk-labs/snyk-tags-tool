from snyk_tags import __version__, tags
from typer.testing import CliRunner

runner = CliRunner()
app = tags.app

def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0

def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"snyk-tags v{__version__}\n" in result.stdout
    