#! /usr/bin/env python3

import logging
import typer

from typing import Optional
from snyk_tags import __app_name__, __version__, apply


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

app = typer.Typer(help="Use snyk-tags to apply tagging to a set of Snyk projects based on the project type")
app.add_typer(apply.app, name="apply", help="Apply tags to the different project types")

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"snyk-tags v{__version__}")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit",
        callback=_version_callback,
        is_eager=True,
    )
) -> None:
    return
