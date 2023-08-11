#! /usr/bin/env python3

import logging

import httpx
import typer
from rich import print
from snyk import SnykClient

from snyk_tags import __app_name__, __version__, attribute, github

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

app = typer.Typer()
app.add_typer(
    github.app,
    name="github",
    help="Use GitHub metadata such as CODEOWNERS and GitHub Topics to add to Snyk projects",
)


# Reach to the API and generate tokens
def create_client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://snyk.io/api/v1", headers={"Authorization": f"token {token}"}
    )


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
    if req.status_code == 422:
        logging.warning(
            f"Tag {key}:{tag} is already applied for Project: {project_name}."
        )
    if req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}."
        )
    return req.status_code, req.json()


# Tagging loop
def apply_tags_to_projects(
    token: str, org_ids: list, name: str, tag: str, key: str
) -> None:
    with create_client(token=token) as client:
        for org_id in org_ids:
            client_v3 = SnykClient(token=token)
            projects = client_v3.organizations.get(org_id).projects.all()

            badname = 0
            rightname = 0
            for project in projects:
                if (
                    project.name == name
                    or project.name.startswith(name + "(")
                    or project.name.startswith(name + ":")
                ):
                    apply_tag_to_project(
                        client=client,
                        org_id=org_id,
                        project_id=project.id,
                        tag=tag,
                        key=key,
                        project_name=project.name,
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
    apply_tags_to_projects(snyktkn, [org_id], target, tagValue, tagKey)


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
):
    typer.secho(
        f"\nAdding the attributes {criticality}, {environment} and {lifecycle} to projects within {target} for easy filtering via the UI",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
    attribute.apply_attributes_to_projects(
        snyktkn, [org_id], target, [criticality], [environment], [lifecycle]
    )
