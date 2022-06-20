#! /usr/bin/env python3

"""
Need to install httpx and python-dotenv to run this script.

```
pip install httpx python-dotenv
```

Additionally, you will need a .env file with two variables in it:
GROUP_ID = (your group id)
AUTH_TOKEN = (your auth token)

Afterwards, use any Python version above 3.6, and run this script. 
It will update the Snyk Code projects in Snyk to have the sast tag.
Once this is run, go into the UI and click on the tags filter in the
projects page (left-hand menu). Select the type tag and sast as the key.
All of your Snyk Code projects will be shown via this filter.
"""


import logging
import os
import httpx
import typer

from typing import Optional
from dotenv import load_dotenv
from snyk_tags import __app_name__, __version__


logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

app = typer.Typer()

def create_client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://snyk.io/api/v1", headers={"Authorization": f"token {token}"}
    )


def get_org_ids(token: str, group_id: str) -> list:
    """
    Get a list of org_ids based on the given group_id
    :param token:
    :param group_id:
    :return: list of org_ids
    """
    org_ids = []

    with create_client(token=token) as client:
        orgs = client.get(f"group/{group_id}/orgs").json()
        for org in orgs.get("orgs"):
            org_ids.append(org["id"])
    return org_ids


def apply_sast_tag_to_project(
    client: httpx.Client, org_id: str, project_id: str
) -> tuple:
    """
    Apply the SAST tag to each given project

    :param client:
    :param org_id:
    :param project_id:
    :return: tuple of the status_code and dictionary of the JSON response
    """
    tag_data = {
        "key": "type",
        "value": "sast",
    }
    req = client.post(f"org/{org_id}/project/{project_id}/tags", data=tag_data)

    if req.status_code == 200:
        logging.info(f"Successfully added tags to Project ID: {project_id}.")

    if req.status_code == 422:
        logging.warning(f"SAST tag is already applied for Project ID: {project_id}.")

    if req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project ID: {project_id}. Error message: {req.json()}."
        )

    return req.status_code, req.json()


def apply_sast_tags_to_sast_projects(token: str, org_ids: list) -> None:
    """
    Apply the tags to all SAST projects within all orgs given in a list
    :param token:
    :param org_ids:
    :return: None
    """
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                if project["type"] == "sast":
                    logging.debug(
                        apply_sast_tag_to_project(
                            client=client, org_id=org_id, project_id=project["id"]
                        )
                    )

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__app_name__} v{__version__}")
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
    ),
) -> None:
    return

@app.command()
def apply(group_id: str = typer.Argument(..., envvar=["GROUP_ID"]), token: str = typer.Argument(..., envvar=["SNYK_TOKEN"])):
#def main():
    # Load variables from configuration file
    load_dotenv()

    #group_id = os.getenv("GROUP_ID")
    #token = os.getenv("AUTH_TOKEN")

    logging.info(
        "This script will add the sast tag to every Snyk Code project in Snyk for easy filtering via the UI"
    )
    org_ids = get_org_ids(token, group_id)
    apply_sast_tags_to_sast_projects(token, org_ids)

