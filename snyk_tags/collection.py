#! /usr/bin/env python3

import logging

import httpx
import typer
from rich import print
from snyk import SnykClient
from typing import Dict

from snyk_tags import __app_name__, __version__, attribute, github

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

logging.getLogger("httpx").setLevel(logging.WARNING)

app = typer.Typer()
app.add_typer(
    github.app,
    name="github",
    help="Use GitHub metadata such as CODEOWNERS and GitHub Topics to add to Snyk projects",
)


# Reach to the API and generate tokens
def create_client(token: str, tenant: str) -> httpx.Client:
    base_url = (
        f"https://api.{tenant}.snyk.io/v1"
        if tenant in ["eu", "au"]
        else "https://api.snyk.io/v1"
    )
    headers = {"Authorization": f"token {token}"}
    return httpx.Client(base_url=base_url, headers=headers)


# Apply tags to a specific project
def apply_tag_to_project(
    client: httpx.Client,
    org_id: str,
    project_id: str,
    tag: str,
    key: str,
    project_name: str,
) -> tuple:
    tag_data = {
        "key": key,
        "value": tag,
    }

    req = client.post(
        f"org/{org_id}/project/{project_id}/tags", data=tag_data, timeout=None
    )

    if req.status_code == 200:
        logging.info(f"Successfully added {tag_data} tags to Project: {project_name}.")
    elif req.status_code == 422:
        logging.warning(
            f"Tag {key}:{tag} is already applied for Project: {project_name}."
        )
    elif req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}."
        )
    return req.status_code, req.json()


# Tagging loop
def apply_tags_to_projects(
    token: str,
    org_ids: list,
    name: str,
    tag: str,
    key: str,
    tenant: str,
    filters: Dict[str, any],
) -> None:
    with create_client(token=token, tenant=tenant) as client:
        for org_id in org_ids:
            base_url = (
                f"https://api.{tenant}.snyk.io/rest"
                if tenant in ["eu", "au"]
                else "https://api.snyk.io/rest"
            )
            client_v3 = SnykClient(
                token=token, url=base_url, version="2023-08-31~experimental"
            )
            params = {"limit": 100, "names_start_with": name, **filters}
            projects = client_v3.get_rest_pages(
                f"/orgs/{org_id}/projects", params=params
            )

            badname = 0
            rightname = 0
            for project in projects:
                if (
                    project["attributes"]["name"] == name
                    or project["attributes"]["name"].startswith(name + "(")
                    or project["attributes"]["name"].startswith(name + ":")
                ):
                    apply_tag_to_project(
                        client=client,
                        org_id=org_id,
                        project_id=project["id"],
                        tag=tag,
                        key=key,
                        project_name=project["attributes"]["name"],
                    )
                    rightname = 1
                else:
                    badname = 1
            if badname == 1 and rightname == 0:
                print(
                    f"[bold red]{name}[/bold red] is not a valid target, please check it is a target within the organization e.g. [bold blue]snyk-labs/snyk-goof[/bold blue]"
                )


# Coloured variables for output
crit = typer.style("critical, high, medium, low", bold=True, fg=typer.colors.MAGENTA)
enviro = typer.style(
    "frontend, backend, internal, 	external, mobile, saas, onprem, hosted, distributed",
    bold=True,
    fg=typer.colors.MAGENTA,
)
life = typer.style(
    "production, development, sandbox", bold=True, fg=typer.colors.MAGENTA
)
repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)


@app.command(help=f"Apply a custom tag to a target, for example {repoexample}")
def tag(
    org_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify the Organization ID where you want to apply the tag",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    target: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Name of the target, for example {repoexample}",
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    tagKey: str = typer.Option(
        ..., help="Tag key: identifier of the tag"  # Default value of comamand
    ),
    tagValue: str = typer.Option(
        ..., help="Tag value: value of the tag"  # Default value of comamand
    ),
):
    typer.secho(
        f"\nAdding the tag key {tagKey} and tag value {tagValue} to projects within {target} for easy filtering via the UI",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
    apply_tags_to_projects(snyktkn, [org_id], target, tagValue, tagKey, tenant=tenant)


# Collection command to apply the attributes to the collection
@app.command(help=f"Apply attributes to a target, for example {repoexample}")
def attributes(
    org_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify the Organization ID where you want to apply the attributes",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    target: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Name of the project collection, for example {repoexample}",
    ),
    criticality: str = typer.Option(
        "", help=f"Criticality attribute: {crit}"  # Default value of comamand
    ),
    environment: str = typer.Option(
        "", help=f"Environment attribute: {enviro}"  # Default value of comamand
    ),
    lifecycle: str = typer.Option(
        "", help=f"Lifecycle attribute: {life}"  # Default value of comamand
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
):
    typer.secho(
        f"\nAdding the attributes {criticality}, {environment} and {lifecycle} to projects within {target} for easy filtering via the UI",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
    attribute.apply_attributes_to_projects(
        snyktkn,
        [org_id],
        target,
        [criticality],
        [environment],
        [lifecycle],
        tenant=tenant,
    )
