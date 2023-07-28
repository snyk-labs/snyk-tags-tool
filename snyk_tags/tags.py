#! /usr/bin/env python3

import typer

from typing import Optional
from snyk_tags import (
    __app_name__,
    __version__,
    files,
    list,
    collection,
    tag,
    remove,
    component,
)

snyk = typer.style("snyk-tags", bold=True)
snykcmd = typer.style("snyk-tags tag --help", bold=True, fg=typer.colors.MAGENTA)
snykcmd2 = typer.style("snyk-tags target --help", bold=True, fg=typer.colors.MAGENTA)
snykcmd3 = typer.style("snyk-tags list --help", bold=True, fg=typer.colors.MAGENTA)
snykcmd4 = typer.style("snyk-tags remove --help", bold=True, fg=typer.colors.MAGENTA)

app = typer.Typer(
    help=f"{snyk} helps you filter Snyk projects by adding or removing product tags and attributes to projects per product or target of projects\n\n To start using it try running:\n\n - {snykcmd} \n\n - {snykcmd2}  \n\n - {snykcmd3}  \n\n - {snykcmd4}",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(
    tag.app,
    name="tag",
    help="Apply product/custom tags based on the product or project type",
)
app.add_typer(
    list.app, name="list", help="List all Snyk project types and all attribute types"
)
app.add_typer(
    collection.app,
    name="target",
    help="Apply custom tags and attributes to all projects within a target e.g Git repo",
)
app.add_typer(
    remove.app,
    name="remove",
    help="Remove tags from a Group and from all projects within a target e.g Git repo",
)
app.add_typer(
    files.app,
    name="fromfile",
    help="Import tags and attributes from a csv file to a target e.g. Git repo",
)
app.add_typer(
    component.app,
    name="component",
    help="Manage software component definitions with Snyk project tags",
)


def main():
    return True


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
