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

# Apply tags
def apply_tag_to_project(
    client: httpx.Client, org_id: str, project_id: str, tag: str, key: str
) -> tuple:
    tag_data = {
        "key": key,
        "value": tag,
    }
    req = client.post(f"org/{org_id}/project/{project_id}/tags", data=tag_data)

    if req.status_code == 200:
        logging.info(f"Successfully added {tag} tags to Project ID: {project_id}.")

    if req.status_code == 422:
        logging.warning(f"{tag} tag is already applied for Project ID: {project_id}.")

    if req.status_code == 404:
        logging.error(f"Project not found, likely a READ-ONLY project. Project ID: {project_id}. Error message: {req.json()}.")

    return req.status_code, req.json()

def apply_tags_to_projects(token: str, org_ids: list, type: str, tag: str, key: str) -> None:
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                if project["type"] == type:
                    logging.debug(
                        apply_tag_to_project(
                            client=client, org_id=org_id, project_id=project["id"], tag=tag, key=key
                        )
                    )

# SAST Command
sasttypes = typer.style("\n sast", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply Code tag to Snyk Code projects (default: sast")
def sast(group_id: str = typer.Option(
            ..., # Default value of comamand
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ),  org_id: str = typer.Option(
            "", # Default value of comamand
            envvar=["ORG_ID"],
            help="Specify one Organization ID to only apply the tag to one organization"
        ), token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  sastType: str = typer.Option(
            "sast", # Default value of comamand
            help=f"Type of Snyk Code projects to apply tags to: {sasttypes}"
        )
    ):

    typer.secho(f"\nAdding the Code tag to {sastType} projects in Snyk for easy filtering via the UI", bold=True)

    org = []
    if org_id == '' or None:
        org_ids = get_org_ids(token, group_id)
        apply_tags_to_projects(token, org_ids, type=sastType, tag='Code', key='Product')
    else:
        org.append(org_id)
        apply_tags_to_projects(token, org, type=sastType, tag='Code', key='Product')

# IaC Command
iactypes = typer.style("\n terraformconfig\n terraformplan\n k8sconfig\n helmconfig\n cloudformationconfig\n armconfig", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply IaC tag to Snyk IaC projects (default: terraformconfig")
def iac(group_id: str = typer.Option(
            ..., # Default value of comamand
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ),  org_id: str = typer.Option(
            "", # Default value of comamand
            envvar=["ORG_ID"],
            help="Specify one Organization ID to only apply the tag to one organization"
        ), token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  iacType: str = typer.Option(
            "terraformconfig", # Default value of comamand
            help=f"Type of Snyk IaC projects to apply tags to: {iactypes}"
        )
    ):

    typer.secho(f"\nAdding the IaC tag to {iacType} projects in Snyk for easy filtering via the UI", bold=True)

    org = []
    if org_id == '' or None:
        org_ids = get_org_ids(token, group_id)
        apply_tags_to_projects(token, org_ids, type=iacType, tag='IaC', key='Product')
    else:
        org.append(org_id)
        apply_tags_to_projects(token, org, type=iacType, tag='IaC', key='Product')

# SCA Command
scatypes = typer.style("\nmaven\n npm\n nuget\n gradle\n pip\n yarn\n gomodules\n rubygems\n composer\n sbt\n golangdep\n cocoapods\n poetry\n govendor\n cpp\n yarn-workspace\n hex\n paket\n golang", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply Open Source tag to a type Snyk Open Source projects (default: maven)")
def sca(group_id: str = typer.Option(
            ..., # Default value of comamand
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ),  org_id: str = typer.Option(
            "", # Default value of comamand,
            envvar=["ORG_ID"],
            help="Specify one Organization ID to only apply the tag to one organization"
        ),  token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  scaType: str = typer.Option(
            "maven", # Default value of comamand
            help=f"Type of Snyk Open Source projects to apply tags to: {scatypes}"
        )
    ):

    typer.secho(f"\nAdding the Open Source tag to {scaType} projects in Snyk for easy filtering via the UI", bold=True)

    org = []
    if org_id == '' or None:
        org_ids = get_org_ids(token, group_id)
        apply_tags_to_projects(token, org_ids, scaType, tag='Open Source', key='Product')
    else:
        org.append(org_id)
        apply_tags_to_projects(token, org, scaType, tag='Open Source', key='Product')

# Container Command
containertypes = typer.style("\n dockerfile\n apk\n deb\n rpm\n linux", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply Container tag to a type Snyk Container projects (default: deb)")
def container(group_id: str = typer.Option(
            ..., # Default value of comamand
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ),  org_id: str = typer.Option(
            "", # Default value of comamand
            envvar=["ORG_ID"],
            help="Specify one Organization ID to only apply the tag to one organization"
        ),  token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  containerType: str = typer.Option(
            "deb", # Default value of comamand
            help=f"Type of Snyk Container projects to apply tags to: {containertypes}"
        )
    ):

    typer.secho(f"\nAdding the Container tag to {containerType} projects in Snyk for easy filtering via the UI", bold=True)

    org = []
    if org_id == '' or None:
        org_ids = get_org_ids(token, group_id)
        apply_tags_to_projects(token, org_ids, containerType, tag='Container', key='Product')
    else:
        org.append(org_id)
        apply_tags_to_projects(token, org, containerType, tag='Container', key='Product')

# Custom Command
@app.command(help="Apply custom tags to the preferred project type")
def custom(group_id: str = typer.Option(
            ..., # Default value of comamand
            help="Group ID of the Snyk Group you want to apply the tags to",
            envvar=["GROUP_ID"]
        ),  org_id: str = typer.Option(
            "", # Default value of comamand
            envvar=["ORG_ID"],
            help="Specify one Organization ID to only apply the tag to one organization"
        ),  token: str = typer.Option(
            ..., # Default value of comamand
            help="SNYK API token",
            envvar=["SNYK_TOKEN"]
        ),  projectType: str = typer.Option(
            ..., # Default value of comamand
            help="Type of Snyk project to apply tags to: \n dockerfile\n apk\n deb\n rpm\n linux"
        ),  tagKey: str = typer.Option(
            ..., # Default value of comamand
            help="Tag key: identifier of the tag"
        ),  tagValue: str = typer.Option(
            ..., # Default value of comamand
            help="Tag value: value of the tag"
        )
    ):

    typer.secho(f"\nAdding the tag key {tagKey} and tag value {tagValue} to {projectType} projects in Snyk for easy filtering via the UI", bold=True)
    org = []
    if org_id == '' or None:
        org_ids = get_org_ids(token, group_id)
        apply_tags_to_projects(token, org_ids, projectType, tagValue, tagKey)
    else:
        org.append(org_id)
        apply_tags_to_projects(token, org, projectType, tagValue, tagKey)



