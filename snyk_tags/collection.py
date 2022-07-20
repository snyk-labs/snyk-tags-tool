#! /usr/bin/env python3

import logging
import httpx
import typer

from snyk_tags import __app_name__, __version__

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

app = typer.Typer()

# Reach to the API and generate tokens
def create_client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://snyk.io/api/v1", headers={"Authorization": f"token {token}"}
    )

# Apply tags to a specific project
def apply_tag_to_project(
    client: httpx.Client, org_id: str, project_id: str, tag: str, key: str, project_name: str
) -> tuple:
    tag_data = {
        "key": key,
        "value": tag,
    }

    req = client.post(f"org/{org_id}/project/{project_id}/tags", data=tag_data)
    
    if req.status_code == 200:
        logging.info(f"Successfully added {tag} tags to Project: {project_name}.")

    if req.status_code == 422:
        logging.warning(f"{tag} tag is already applied for Project: {project_name}.")

    if req.status_code == 404:
        logging.error(f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}.")
    
    return req.status_code, req.json()

#
def apply_tags_to_projects(token: str, org_ids: list, name: str, tag: str, key: str) -> None:
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                if project["name"].startswith(name):
                    apply_tag_to_project(
                            client=client, org_id=org_id, project_id=project["id"], tag=tag, key=key, project_name=project["name"]
                        )

repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)

@app.command(help=f"Apply a custom tag to a project collection\n\n Use the name you see in the collection as the name: name={repoexample} to tag everything under that repo or CLI import")
def tag(org_id: str = typer.Option(
            ..., # Default value of comamand
            envvar=["ORG_ID"],
            help="Specify one or more Organization ID where you want to apply the tag"
        ),  token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  collectionName: str = typer.Option(
            ..., # Default value of comamand
            help=f"Name of the project collection, for example {repoexample}"
        ),  tagKey: str = typer.Option(
            ..., # Default value of comamand
            help="Tag key: identifier of the tag"
        ),  tagValue: str = typer.Option(
            ..., # Default value of comamand
            help="Tag value: value of the tag"
        )
    ):
    typer.secho(f"\nAdding the tag key {tagKey} and tag value {tagValue} to projects within {collectionName} for easy filtering via the UI", bold=True)
    apply_tags_to_projects(token,[org_id], collectionName, tagValue, tagKey)