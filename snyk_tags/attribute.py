#! /usr/bin/env python3

import json
import logging

import httpx
import typer
from rich import print
from snyk import SnykClient

from snyk_tags import __app_name__, __version__

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

logging.getLogger("httpx").setLevel(logging.WARNING)

app = typer.Typer()


# Reach to the API and generate tokens
def create_client(token: str, tenant: str) -> httpx.Client:
    base_url = (
        f"https://api.{tenant}.snyk.io/v1"
        if tenant in ["eu", "au"]
        else "https://api.snyk.io/v1"
    )
    headers = {"Authorization": f"token {token}", "Content-Type": "application/json"}
    return httpx.Client(base_url=base_url, headers=headers)


# Apply attributes to a specific project
def apply_attributes_to_project(
    client: httpx.Client,
    org_id: str,
    project_id: str,
    criticality: list,
    environment: list,
    lifecycle: list,
    project_name: str,
) -> tuple:
    if criticality.count("") == 1:
        criticality.remove("")

    if environment.count("") == 1:
        environment.remove("")

    if lifecycle.count("") == 1:
        lifecycle.remove("")

    attribute_data = {
        "criticality": criticality,
        "environment": environment,
        "lifecycle": lifecycle,
    }

    req = client.post(
        f"org/{org_id}/project/{project_id}/attributes",
        data=json.dumps(attribute_data).replace("'", '"'),
        timeout=None,
    )

    attribute_data = typer.style(attribute_data, bold=True, fg=typer.colors.MAGENTA)
    criticality = typer.style(criticality, bold=True, fg=typer.colors.MAGENTA)
    environment = typer.style(environment, bold=True, fg=typer.colors.MAGENTA)
    lifecycle = typer.style(lifecycle, bold=True, fg=typer.colors.MAGENTA)

    if req.status_code == 200:
        logging.info(
            f"Successfully added {criticality},{environment},{lifecycle} attributes to Project: {project_name}."
        )
    elif req.status_code == 422:
        logging.warning(
            f"Data {attribute_data} cannot be processed, make sure you have written the correct values (refer to help or Readme) and that they are in low caps. Error message: {req.json()}."
        )
    elif req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}."
        )
    elif req.status_code == 500:
        logging.error(
            f"Error message: {req.json()}. Please contact eric.fernandez@snyk.io."
        )
    return req.status_code, req.json()


# Apply attributes to projects within a collection
def apply_attributes_to_projects(
    token: str,
    org_ids: list,
    name: str,
    criticality: list,
    environment: list,
    lifecycle: list,
    tenant: str,
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
            params = {"limit": 100}
            projects = client_v3.get_rest_pages(
                f"/orgs/{org_id}/projects", params=params
            )

            badname = 0
            rightname = 0

            for project in projects:
                if project["attributes"]["name"].startswith(name):
                    apply_attributes_to_project(
                        client=client,
                        org_id=org_id,
                        project_id=project["id"],
                        criticality=criticality,
                        environment=environment,
                        lifecycle=lifecycle,
                        project_name=project["attributes"]["name"],
                    )
                    rightname = 1
                else:
                    badname = 1
            if badname == 1 and rightname == 0:
                print(
                    f"[bold red]{name}[/bold red] is not a valid target, please check it is a target within the organization e.g. [bold blue]snyk-labs/snyk-goof[/bold blue]"
                )
