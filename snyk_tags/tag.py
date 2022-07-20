#! /usr/bin/env python3

import logging
import httpx
import typer

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
        base_url="https://snyk.io/api/v1", headers={"Authorization": f"token {token}"}
    )

# Get all organizations within a Group
def get_org_ids(token: str, group_id: str) -> list:
    org_ids = []
    with create_client(token=token) as client:
        req = client.get(f"group/{group_id}/orgs")
        if req.status_code == 404:
            logging.error(f"Group id: {group_id} is invalid. Error message: {req.json()}.")
        orgs = client.get(f"group/{group_id}/orgs").json()
        
        for org in orgs.get("orgs"):
            org_ids.append(org["id"])
    return org_ids

# Apply tags using the project tag API
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

def apply_tags_to_projects(token: str, org_ids: list, types: list, tag: str, key: str) -> None:
    with create_client(token=token) as client:
        for org_id in org_ids:
            projects = client.post(f"org/{org_id}/projects").json()
            for project in projects.get("projects"):
                for type in types:
                    if project["type"] == type:
                        logging.debug(
                            apply_tag_to_project(
                                client=client, org_id=org_id, project_id=project["id"], tag=tag, key=key, project_name=project["name"]
                            )
                        )

# SAST Command
sasttypes = typer.style("\n sast", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply Code tag to Snyk Code projects")
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
            "", # Default value of comamand
            help=f"Type of Snyk Code projects to apply tags to: {sasttypes}"
        )
    ):

    org = []
    type = []
    if org_id == '' or None:
        if sastType == '' or None:
            sastType = ["sast"]
            typer.secho(f"\nAdding the Code tag to {sastType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org_ids, sastType, tag='Code', key='Product')
        else:
            type.append(sastType)
            typer.secho(f"\nAdding the Code tag to {sastType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org_ids, type, tag='Code', key='Product')
    else:
        if sastType == '' or None:
            sastType = ["sast"]
            typer.secho(f"\nAdding the Code tag to {sastType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org, sastType, tag='Code', key='Product')
        else:
            type.append(sastType)
            typer.secho(f"\nAdding the Code tag to {sastType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org_ids, type, tag='Code', key='Product')



# IaC Command
iactypes = typer.style("\n terraformconfig\n terraformplan\n k8sconfig\n helmconfig\n cloudformationconfig\n armconfig", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply IaC tag to Snyk IaC projects")
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
            "", # Default value of comamand
            help=f"Type of Snyk IaC projects to apply tags to: {iactypes}"
        )
    ):

    org = []
    type = []
    if org_id == '' or None:
        if iacType == '' or None:
            iacType=["terraformconfig", "terraformplan", "k8sconfig", "helmconfig", "cloudformationconfig", "armconfig"]
            typer.secho(f"\nAdding the IaC tag to {iacType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org_ids, iacType, tag='IaC', key='Product')
        else:
            type.append(iacType)
            typer.secho(f"\nAdding the IaC tag to {iacType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org, type, tag='IaC', key='Product')
    else:
        if iacType == '' or None:
            iacType=["terraformconfig", "terraformplan", "k8sconfig", "helmconfig", "cloudformationconfig", "armconfig"]
            typer.secho(f"\nAdding the IaC tag to {iacType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org, iacType, tag='IaC', key='Product')
        else:
            type.append(iacType)
            typer.secho(f"\nAdding the IaC tag to {iacType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org, type, tag='IaC', key='Product')



# SCA Command
scatypes = typer.style("\nmaven\n npm\n nuget\n gradle\n pip\n yarn\n gomodules\n rubygems\n composer\n sbt\n golangdep\n cocoapods\n poetry\n govendor\n cpp\n yarn-workspace\n hex\n paket\n golang", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply Open Source tag to Snyk Open Source projects")
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
            "", # Default value of comamand
            help=f"Type of Snyk Open Source projects to apply tags to (default:all): {scatypes}"
        )
    ):

    org = []
    type = []
    if org_id == '' or None:
        if scaType == '' or None:
            scaType = ["maven","npm","nuget", "gradle", "pip", "yarn", "gomodules", "rubygems", "composer", "sbt", "golangdep", "cocoapods", "poetry", "govendor", "cpp", "yarn-workspace", "hex", "paket", "golang"]
            typer.secho(f"\nAdding the Open Source tag to {scaType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org_ids, scaType, tag='Open Source', key='Product')
        else:
            type.append(scaType)
            typer.secho(f"\nAdding the Open Source tag to {scaType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org_ids, type, tag='Open Source', key='Product')
    else:
        if scaType == '' or None:
            scaType = ["maven","npm","nuget", "gradle", "pip", "yarn", "gomodules", "rubygems", "composer", "sbt", "golangdep", "cocoapods", "poetry", "govendor", "cpp", "yarn-workspace", "hex", "paket", "golang"]
            typer.secho(f"\nAdding the Open Source tag to {scaType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org, scaType, tag='Open Source', key='Product')
        else:
            type.append(scaType)
            typer.secho(f"\nAdding the Open Source tag to {scaType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org, type, tag='Open Source', key='Product')



# Container Command
containertypes = typer.style("\n dockerfile\n apk\n deb\n rpm\n linux", bold=True, fg=typer.colors.MAGENTA)
@app.command(help="Apply Container tag to Snyk Container projects")
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
            "", # Default value of comamand
            help=f"Type of Snyk Container projects to apply tags to (default:all): {containertypes}"
        )
    ):

    org = []
    type =[]
    if org_id == '' or None:
        if containerType == '' or None:
            containerType= ["dockerfile", "apk", "deb", "rpm", "linux"]
            typer.secho(f"\nAdding the Container tag to {containerType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org_ids, containerType, tag='Container', key='Product')
        else:
            type.append(containerType)
            typer.secho(f"\nAdding the Container tag to {containerType} projects in Snyk for easy filtering via the UI", bold=True)
            org_ids = get_org_ids(token, group_id)
            apply_tags_to_projects(token, org_ids, type, tag='Container', key='Product')
    else:
        if containerType == '' or None:
            containerType= ["dockerfile", "apk", "deb", "rpm", "linux"]
            typer.secho(f"\nAdding the Container tag to {containerType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org, containerType, tag='Container', key='Product')
        else:
            type.append(containerType)
            typer.secho(f"\nAdding the Container tag to {containerType} projects in Snyk for easy filtering via the UI", bold=True)
            org.append(org_id)
            apply_tags_to_projects(token, org, type, tag='Container', key='Product')

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
            help=f"Type of Snyk project to apply tags to (choose one): {sasttypes}, {containertypes}, {scatypes}, {iactypes}"
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
    type =[]
    type.append(projectType)
    if org_id == '' or None:
        org_ids = get_org_ids(token, group_id)
        apply_tags_to_projects(token, org_ids, type, tagValue, tagKey)
    else:
        org.append(org_id)
        apply_tags_to_projects(token, org, type, tagValue, tagKey)

