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

# SAST Command
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
def sast(group_id: str = typer.Option(
            ..., 
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ), token: str = typer.Option(
            ...,
            help="SNYK API token",
            envvar=["SNYK_TOKEN"])
    ):

    logging.info(
        "This script will add the sast tag to every Snyk Code project in Snyk for easy filtering via the UI"
    )
    org_ids = get_org_ids(token, group_id)
    apply_sast_tags_to_sast_projects(token, org_ids)


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
        logging.warning(f"IAC tag is already applied for Project ID: {project_id}.")

    if req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project ID: {project_id}. Error message: {req.json()}."
        )

    return req.status_code, req.json()


def apply_iac_tags_to_iac_projects(token: str, org_ids: list) -> None:
    """
    Apply the tags to all IAC projects within all orgs given in a list
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
def iac(group_id: str = typer.Option(
            ..., 
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ), token: str = typer.Option(
            ...,
            help="SNYK API token",
            envvar=["SNYK_TOKEN"])
    ):

    logging.info(
        "This script will add the iac tag to every Snyk IaC project in Snyk for easy filtering via the UI"
    )
    org_ids = get_org_ids(token, group_id)
    apply_iac_tags_to_iac_projects(token, org_ids)

# SCA Command
def apply_sca_tag_to_project(
    client: httpx.Client, org_id: str, project_id: str
) -> tuple:
    """
    Apply the SCA tag to each given project

    :param client:
    :param org_id:
    :param project_id:
    :return: tuple of the status_code and dictionary of the JSON response
    """
    tag_data = {
        "key": "type",
        "value": "sca",
    }
    req = client.post(f"org/{org_id}/project/{project_id}/tags", data=tag_data)

    if req.status_code == 200:
        logging.info(f"Successfully added tags to Project ID: {project_id}.")

    if req.status_code == 422:
        logging.warning(f"SCA tag is already applied for Project ID: {project_id}.")

    if req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project ID: {project_id}. Error message: {req.json()}."
        )

    return req.status_code, req.json()


def apply_sca_tags_to_sca_projects(token: str, org_ids: list, scaType: str) -> None:
    """
    Apply the tags to all SCA projects within all orgs given in a list
    :param token:
    :param org_ids:
    :return: None
    """
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                if project["type"] == scaType:
                    logging.debug(
                        apply_sca_tag_to_project(
                            client=client, org_id=org_id, project_id=project["id"]
                        )
                    )

@app.command()
def sca(group_id: str = typer.Option(
            ..., 
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ),  token: str = typer.Option(
            ...,
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  scaType: str = typer.Option(
            "maven",
            help="Type of package to update tags: maven, npm"
        )
    ):

    logging.info(
        "This script will add the SCA tag to every Snyk Open Source project in Snyk for easy filtering via the UI"
    )
    org_ids = get_org_ids(token, group_id)
    apply_sca_tags_to_sca_projects(token, org_ids, scaType)

# Container Command
def apply_container_tag_to_project(
    client: httpx.Client, org_id: str, project_id: str
) -> tuple:
    """
    Apply the Container tag to each given project

    :param client:
    :param org_id:
    :param project_id:
    :return: tuple of the status_code and dictionary of the JSON response
    """
    tag_data = {
        "key": "type",
        "value": "container",
    }
    req = client.post(f"org/{org_id}/project/{project_id}/tags", data=tag_data)

    if req.status_code == 200:
        logging.info(f"Successfully added tags to Project ID: {project_id}.")

    if req.status_code == 422:
        logging.warning(f"Container tag is already applied for Project ID: {project_id}.")

    if req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project ID: {project_id}. Error message: {req.json()}."
        )

    return req.status_code, req.json()


def apply_cont_tags_to_cont_projects(token: str, org_ids: list, scaType: str) -> None:
    """
    Apply the tags to all Container projects within all orgs given in a list
    :param token:
    :param org_ids:
    :return: None
    """
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                if project["type"] == scaType:
                    logging.debug(
                        apply_container_tag_to_project(
                            client=client, org_id=org_id, project_id=project["id"]
                        )
                    )

@app.command()
def container(group_id: str = typer.Option(
            ..., 
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ),  token: str = typer.Option(
            ...,
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  containerType: str = typer.Option(
            "deb",
            help="Type of container to update tags: Dockerfile, deb"
        )
    ):

    logging.info(
        "This script will add the container tag to every Snyk Container project in Snyk for easy filtering via the UI"
    )
    org_ids = get_org_ids(token, group_id)
    apply_cont_tags_to_cont_projects(token, org_ids, containerType)