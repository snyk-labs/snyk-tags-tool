#! /usr/bin/env python3

import logging
import httpx
import typer
import json
from rich import print

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

# Apply attributes to a specific project
def apply_attributes_to_project(
    client: httpx.Client, org_id: str, project_id: str, criticality: list, environment: list, lifecycle: list, project_name: str
) -> tuple:
    attribute_data = {
        "criticality": criticality,
        "environment": environment,
        "lifecycle": lifecycle
    }
    
    req = client.post(f"org/{org_id}/project/{project_id}/attributes", data=json.dumps(attribute_data))
    
    attribute_data = typer.style(attribute_data, bold=True, fg=typer.colors.MAGENTA)
    criticality = typer.style(criticality, bold=True, fg=typer.colors.MAGENTA)
    environment = typer.style(environment, bold=True, fg=typer.colors.MAGENTA)
    lifecycle = typer.style(lifecycle, bold=True, fg=typer.colors.MAGENTA)
    if req.status_code == 200:
        logging.info(f"Successfully added {criticality},{environment},{lifecycle} attributes to Project: {project_name}.")
    if req.status_code == 422:
        logging.warning(f"Data {attribute_data} cannot be processed, make sure you have written the correct values (refer to help or Readme) and that they are in low caps. Error message: {req.json()}.")
    if req.status_code == 404:
        logging.error(f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}.")
    if req.status_code == 500:
        logging.error(f"Error message: {req.json()}. Please contact eric.fernandez@snyk.io.")
    return req.status_code, req.json()

# Apply attributes to projects within a collection
def apply_attributes_to_projects(token: str, org_ids: list, name: str, criticality: list, environment: list, lifecycle: list) -> None:
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            isname = 0
            for project in projects.get("projects"):
                if project["name"].startswith(name):
                    apply_attributes_to_project(
                            client=client, org_id=org_id, project_id=project["id"], criticality=criticality, environment=environment, lifecycle=lifecycle, project_name=project["name"]
                        )
                else:
                    isname=1
            if isname == 1:
                print(f"[bold red]{name}[/bold red] is not a valid target, please check it is a target within the organization e.g. [bold blue]snyk-labs/snyk-goof[/bold blue]")
