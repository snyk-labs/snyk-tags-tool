#! /usr/bin/env python3

import typer

from typing import Optional
from snyk_tags import __app_name__, __version__, apply, list, collection

snyk = typer.style("snyk-tags", bold=True)
snykcmd = typer.style("snyk-tags apply --help", bold=True, fg=typer.colors.MAGENTA)

app = typer.Typer(
    help=f"{snyk} helps you filter Snyk projects by adding product tags to each Snyk product based on the project type\n\n To start using it try running {snykcmd} \n",
    add_completion=False,
    no_args_is_help=True
    )
app.add_typer(apply.app, name="apply", help="Apply product/custom tags based on project type, select which tag to apply")
app.add_typer(list.app, name="list", help="List all project types of a Snyk product")
app.add_typer(collection.app, name="collection", help="Apply custom tags to all projects within a collection e.g Git repo")

def main():
    print(snyk)

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
