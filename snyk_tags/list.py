#! /usr/bin/env python3
from rich import print_json
import typer
from rich.console import Console
from rich.table import Table
import json
import httpx

from snyk_tags import __app_name__, __version__

app = typer.Typer()
console = Console()
"""
List all the different project types and attribute types
"""


# List all project types command
@app.command(help="List all Snyk project types")
def types():
    snykcmd = typer.style(
        "snyk-tags target tag or snyk-tags tag custom",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
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
    snykcmd = typer.style(
        "snyk-tags target attributes", bold=True, fg=typer.colors.MAGENTA
    )
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


# Functions for tags listing command
def create_client(token: str, tenant: str) -> httpx.Client:
    base_url = (
        f"https://api.{tenant}.snyk.io/v1"
        if tenant in ["eu", "au"]
        else "https://api.snyk.io/v1"
    )
    headers = {"Authorization": f"token {token}"}
    return httpx.Client(base_url=base_url, headers=headers)


# Get the tags from a group
def find_tags(token: str, group_id: str, jsonflag: bool, tenant: str) -> tuple:
    with create_client(token=token, tenant=tenant) as client:
        req = client.get(f"group/{group_id}/tags")
        group = client.get(f"group/{group_id}/orgs", timeout=None).json()
        group_name = group["name"]
        if req.status_code == 200:
            if jsonflag is False:
                print(f"These are the tags in Group: {group_name}")
                table = Table("Key", "Value")
                for tags in req.json().get("tags"):
                    key = tags.get("key")
                    value = tags.get("value")
                    table.add_row(key, value)
                console.print(table)
            elif jsonflag is True:
                print(json.dumps(req.json()))
        if req.status_code == 404:
            print(f"Group {group_name} not found. Error message: {req.json()}.")
        return req.status_code, req.json()


# List existing tags in a Group Command
@app.command(help="List all existing tags in a Group")
def tags(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["GROUP_ID"],
        help="Specify the Group you want to see the tags from",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with Group admin access",
        envvar=["SNYK_TOKEN"],
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    json: bool = typer.Option(
        False,
        "--json",  # Default value of comamand
        help=f"Output into json format (default is a table), use --json to change output.",
    ),
):
    find_tags(
        snyktkn,
        group_id,
        json,
        tenant=tenant,
    )
