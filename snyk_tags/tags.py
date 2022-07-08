#! /usr/bin/env python3

import typer

from typing import Optional
from snyk_tags import __app_name__, __version__, apply, list

app = typer.Typer(help="Use snyk-tags to apply tagging to a set of Snyk projects based on the project type", add_completion=False)
app.add_typer(apply.app, name="apply", help="Apply tags to the different project types")
app.add_typer(list.app, name="list", help=f"List all project types of a Snyk product")

"""
Testing ways of outputing a default command
snyk = typer.style("snyk-tags", bold=True)
snykcmd = typer.style("snyk-tags apply --help", bold=True, fg=typer.colors.MAGENTA)
typer.echo("\n")
typer.echo(f"{snyk} helps you filter Snyk projects by adding product tags per product type")
typer.echo(f"To start using it try running {snykcmd} \n")
"""

def _version_callback(value: bool) -> None:
    if value:
        typer.secho(f"snyk-tags v{__version__}", bold=True)
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
