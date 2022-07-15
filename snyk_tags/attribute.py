#! /usr/bin/env python3

import logging
import httpx
import typer
import json

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
        base_url="https://snyk.io/api/v1", headers={"Authorization": f"token {token}", 'Content-Type': 'application/json'} 
    )

# Apply tags to a specific project
def apply_tag_to_project(
    client: httpx.Client, org_id: str, project_id: str, criticality: list, environment: list, lifecycle: list, project_name: str
) -> tuple:
    attribute_data = {
        "criticality": criticality,
        "environment": environment,
        "lifecycle": lifecycle
    }
    
    req = client.post(f"org/{org_id}/project/{project_id}/attributes", data=json.dumps(attribute_data))
    
    attribute_data = typer.style(attribute_data, bold=True, fg=typer.colors.MAGENTA)
    if req.status_code == 200:
        logging.info(f"Successfully added {attribute_data} attributes to Project: {project_name}.")
    
    if req.status_code == 422:
        logging.warning(f"Data {attribute_data} cannot be processed, make sure you have written the correct values (refer to help or Readme) and that they are in low caps.")

    if req.status_code == 404:
        logging.error(f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}.")
    
    if req.status_code == 500:
        logging.error(f"Error {req.status_code}: Internal Server Error. Please contact eric.fernandez@snyk.io.")
    
    return req.status_code, req.json()

#
def apply_tags_to_projects(token: str, org_ids: list, name: str, criticality: list, environment: list, lifecycle: list) -> None:
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                if project["name"].startswith(name):
                    apply_tag_to_project(
                            client=client, org_id=org_id, project_id=project["id"], criticality=criticality, environment=environment, lifecycle=lifecycle, project_name=project["name"]
                        )

# Coloured variables for output
repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)
crit = typer.style("critical, high, medium, low", bold=True, fg=typer.colors.MAGENTA)
enviro = typer.style("frontend, backend, internal, 	external, mobile, saas, onprem, hosted, distributed", bold=True, fg=typer.colors.MAGENTA)
life = typer.style("production, development, sandbox", bold=True, fg=typer.colors.MAGENTA)

# Collection command to apply the attributes to the collection
@app.command(help=f"Apply attributes to a project collection\n\n Use the name you see in the collection as the name: name={repoexample} to set the attributes for everything under that repo, container or CLI import")
def collection(org_id: str = typer.Option(
            ..., # Default value of comamand
            envvar=["ORG_ID"],
            help="Specify the Organization ID where you want to apply the attributes"
        ),  token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  collectionName: str = typer.Option(
            ..., # Default value of comamand
            help=f"Name of the project collection, for example {repoexample}"
        ),  criticality: str = typer.Option(
            ..., # Default value of comamand
            help=f"Criticality attribute: {crit}"
        ),  environment: str = typer.Option(
            ..., # Default value of comamand
            help=f"Environment attribute: {enviro}"
        ),  lifecycle: str = typer.Option(
            ..., # Default value of comamand
            help=f"Lifecycle attribute: {life}"
        )
    ):
    typer.secho(f"\nAdding the attributes {criticality}, {environment} and {lifecycle} to projects within {collectionName} for easy filtering via the UI", bold=True, fg=typer.colors.MAGENTA)
    apply_tags_to_projects(token,[org_id], collectionName, [criticality], [environment], [lifecycle])