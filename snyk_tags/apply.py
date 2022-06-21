#! /usr/bin/env python3

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

# SAST Command
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
        req = client.get(f"group/{group_id}/orgs")
        if req.status_code == 404:
            logging.error(
            f"Group id: {group_id} is invalid. Error message: {req.json()}."
        )
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

@app.command()
def sast(group_id: str = typer.Argument(..., envvar=["GROUP_ID"]), token: str = typer.Argument(..., envvar=["SNYK_TOKEN"])):

    # Load variables from configuration file
    load_dotenv()    

    logging.info(
        "This script will add the sast tag to every Snyk Code project in Snyk for easy filtering via the UI"
    )
    if group_id is not None and token is not None:
        org_ids = get_org_ids(token, group_id)
        apply_sast_tags_to_sast_projects(token, org_ids)
    elif os.getenv("GROUP_ID") is not None and os.getenv("SNYK_TOKEN") is not None:
        group_id = os.getenv("GROUP_ID")
        token = os.getenv("SNYK_TOKEN")
        org_ids = get_org_ids(token, group_id)
        sast.apply_sast_tags_to_sast_projects(token, org_ids)
    else:
        logging.error(
            f"Credentials not valid"
        )


# IaC Command
def apply_iac_tag_to_project(
    client: httpx.Client, org_id: str, project_id: str
) -> tuple:
    """
    Apply the IaC tag to each given project

    :param client:
    :param org_id:
    :param project_id:
    :return: tuple of the status_code and dictionary of the JSON response
    """
    tag_data = {
        "key": "type",
        "value": "iac",
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


def apply_iac_tags_to_iac_projects(token: str, org_ids: list) -> None:
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
                        apply_iac_tag_to_project(
                            client=client, org_id=org_id, project_id=project["id"]
                        )
                    )

@app.command()
def iac(group_id: str = typer.Argument(..., envvar=["GROUP_ID"]), token: str = typer.Argument(..., envvar=["SNYK_TOKEN"])):

    # Load variables from configuration file
    load_dotenv()    

    logging.info(
        "This script will add the sast tag to every Snyk Code project in Snyk for easy filtering via the UI"
    )
    if group_id is not None and token is not None:
        org_ids = get_org_ids(token, group_id)
        apply_iac_tags_to_iac_projects(token, org_ids)
    elif os.getenv("GROUP_ID") is not None and os.getenv("SNYK_TOKEN") is not None:
        group_id = os.getenv("GROUP_ID")
        token = os.getenv("SNYK_TOKEN")
        org_ids = get_org_ids(token, group_id)
        apply_iac_tags_to_iac_projects(token, org_ids)
    else:
        logging.error(
            f"Credentials not valid"
        )