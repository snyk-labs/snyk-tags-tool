#! /usr/bin/env python3
import typer
from rich.console import Console
from rich.table import Table

from snyk_tags import __app_name__, __version__

app = typer.Typer()
console = Console()
'''
List all the different project types and attribute types
'''

# List all project types command
@app.command(help="List all Snyk project types")
def types():
    snykcmd = typer.style("snyk-tags target tag or snyk-tags tag custom", bold=True, fg=typer.colors.MAGENTA)
    typer.echo(f"These are all the attribute types you can apply with {snykcmd}")
    table = Table("Snyk IaC", "Snyk Open Source", "Snyk Container", "Snyk Code")
    table.add_row("terraformconfig", "maven", "dockerfile", "sast")
    table.add_row("dockerfile", "npm", "apk", "")
    table.add_row("terraformplan", "nuget", "deb", "")
    table.add_row("k8sconfig", "gradle", "rpm", "")
    table.add_row("helmconfig", "pip", "linux", "")
    table.add_row("cloudformationconfig", "yarn", "", "")
    table.add_row("armconfig", "gomodules", "", "")
    table.add_row("", "rubygems", "", "")
    table.add_row("", "composer", "", "")
    table.add_row("", "sbt", "", "")
    table.add_row("", "golangdep", "", "")
    table.add_row("", "cocoapods", "", "")
    table.add_row("", "poetry", "", "")
    table.add_row("", "govendor", "", "")
    table.add_row("", "cpp", "", "")
    table.add_row("", "yarn-workspace", "", "")
    table.add_row("", "hex", "", "")
    table.add_row("", "paket", "", "")
    table.add_row("", "golang", "", "")
    console.print(table)

# List Attributes Command
@app.command(help="List all Snyk attribute")
def attributes():
    snykcmd = typer.style("snyk-tags target attributes", bold=True, fg=typer.colors.MAGENTA)
    typer.echo(f"These are all the attribute types you can apply with {snykcmd}")
    table = Table("Criticality", "Environment", "Lifecycle")
    table.add_row("critical", "frontend", "production")
    table.add_row("high", "backend", "development")
    table.add_row("medium", "internal", "sandbox")
    table.add_row("low", "external", "")
    table.add_row("", "mobile", "")
    table.add_row("", "saas", "")
    table.add_row("", "onprem", "")
    table.add_row("", "hosted", "")
    table.add_row("", "distributed", "")
    console.print(table)
