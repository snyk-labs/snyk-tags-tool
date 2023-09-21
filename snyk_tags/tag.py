#! /usr/bin/env python3

import logging
import re

import httpx
import typer
from rich import print
from snyk import SnykClient

from snyk_tags import __app_name__, __version__
from snyk_tags.lib.api import Api

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
    headers = {"Authorization": f"token {token}"}
    return httpx.Client(base_url=base_url, headers=headers)


# Get all organizations within a Group
def get_org_ids(token: str, group_id: str, tenant: str) -> list:
    org_ids = []
    with create_client(token=token, tenant=tenant) as client:
        req = client.get(f"group/{group_id}/orgs", timeout=None)
        if req.status_code == 404:
            logging.error(
                f"Group id: {group_id} is invalid. Error message: {req.json()}."
            )
        orgs = client.get(f"group/{group_id}/orgs").json()

        for org in orgs.get("orgs"):
            org_ids.append(org["id"])
    return org_ids


# Apply tags using the project tag API
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
        logging.info(f"Successfully added {tag} tag to Project: {project_name}.")
    elif req.status_code == 422:
        logging.warning(f"{tag} tag is already applied for Project: {project_name}.")
    elif req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}."
        )
    return req.status_code, req.json()


def apply_tags_to_projects(
    token: str,
    org_ids: list,
    types: list,
    tag: str,
    key: str,
    addprojecttype: bool,
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

            for project in projects:
                if project["attributes"]["type"] in types:
                    logging.debug(
                        apply_tag_to_project(
                            client=client,
                            org_id=org_id,
                            project_id=project["id"],
                            tag=tag,
                            key=key,
                            project_name=project["attributes"]["name"],
                        )
                    )
                    if addprojecttype == True:
                        logging.debug(
                            apply_tag_to_project(
                                client=client,
                                org_id=org_id,
                                project_id=project["id"],
                                tag=project["attributes"]["type"],
                                key="Type",
                                project_name=project["attributes"]["name"],
                            )
                        )


def apply_tags_to_projects_by_name(
    token: str,
    org_ids: list,
    name: str,
    ignorecase: bool,
    tag: str,
    key: str,
    tenant: str,
) -> None:
    exp = name.replace("\\", "\\\\") + "+"
    p = re.compile(exp, re.IGNORECASE) if ignorecase else re.compile(exp)
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

            for project in projects:
                if p.search(project["attributes"]["name"]):
                    logging.debug(
                        apply_tag_to_project(
                            client=client,
                            org_id=org_id,
                            project_id=project["id"],
                            tag=tag,
                            key=key,
                            project_name=project["attributes"]["name"],
                        )
                    )


# SAST Command
sasttypes = typer.style("\n sast", bold=True, fg=typer.colors.MAGENTA)


@app.command(help="Apply Code tag to Snyk Code projects - Product:Code")
def sast(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        help="Group ID of the Snyk Group you want to apply the tags to",
        envvar=["GROUP_ID"],
    ),
    org_id: str = typer.Option(
        "",  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify one Organization ID to only apply the tag to one organization",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    sastType: str = typer.Option(
        "",  # Default value of comamand
        help=f"Type of Snyk Code projects to apply tags to: {sasttypes}",
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    addprojecttype: bool = typer.Option(
        False,
        "--addprojecttype",  # Default value of comamand
        help=f"Add an additional tag that will cover the project type e.g. Type:sast (default is false), use --addprojecttype to turn into True.",
    ),
):
    type = ["sast"] if sastType is None or sastType == "" else [sastType]
    orgs = (
        get_org_ids(snyktkn, group_id, tenant)
        if org_id is None or org_id == ""
        else [org_id]
    )
    typer.secho(
        f"\nAdding the Code tag to {type} projects in Snyk for easy filtering via the UI",
        bold=True,
    )
    apply_tags_to_projects(
        snyktkn,
        orgs,
        type,
        tag="Code",
        key="Product",
        tenant=tenant,
        addprojecttype=addprojecttype,
    )


# IaC Command
iactypes = typer.style(
    "\n terraformconfig\n terraformplan\n k8sconfig\n helmconfig\n cloudformationconfig\n armconfig",
    bold=True,
    fg=typer.colors.MAGENTA,
)


@app.command(help="Apply IaC tag to Snyk IaC projects - Product:IaC")
def iac(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        help="Group ID of the Snyk Group you want to apply the tags to",
        envvar=["GROUP_ID"],
    ),
    org_id: str = typer.Option(
        "",  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify one Organization ID to only apply the tag to one organization",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    iacType: str = typer.Option(
        "",  # Default value of comamand
        help=f"Type of Snyk IaC projects to apply tags to: {iactypes}",
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    addprojecttype: bool = typer.Option(
        False,
        "--addprojecttype",  # Default value of comamand
        help=f"Add an additional tag that will cover the project type e.g. Type:terraformplan (default is false), use --addprojecttype to turn into True.",
    ),
):
    type = (
        [
            "terraformconfig",
            "terraformplan",
            "k8sconfig",
            "helmconfig",
            "cloudformationconfig",
            "armconfig",
        ]
        if iacType is None or iacType == ""
        else [iacType]
    )
    orgs = (
        get_org_ids(snyktkn, group_id, tenant)
        if org_id is None or org_id == ""
        else [org_id]
    )
    typer.secho(
        f"\nAdding the IaC tag to {iacType} projects in Snyk for easy filtering via the UI",
        bold=True,
    )
    apply_tags_to_projects(
        snyktkn,
        orgs,
        type,
        tag="IaC",
        key="Product",
        tenant=tenant,
        addprojecttype=addprojecttype,
    )


# SCA Command
scatypes = typer.style(
    "\nmaven\n npm\n nuget\n gradle\n pip\n yarn\n gomodules\n rubygems\n composer\n sbt\n golangdep\n cocoapods\n poetry\n govendor\n cpp\n yarn-workspace\n hex\n paket\n golang",
    bold=True,
    fg=typer.colors.MAGENTA,
)


@app.command(
    help="Apply Open Source tag to Snyk Open Source projects - Product:OpenSource"
)
def sca(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        help="Group ID of the Snyk Group you want to apply the tags to",
        envvar=["GROUP_ID"],
    ),
    org_id: str = typer.Option(
        "",  # Default value of comamand,
        envvar=["ORG_ID"],
        help="Specify one Organization ID to only apply the tag to one organization",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    addprojecttype: bool = typer.Option(
        False,
        "--addprojecttype",  # Default value of comamand
        help=f"Add an additional tag that will cover the project type e.g. Type:maven (default is false), use --addprojecttype to turn into True.",
    ),
    scaType: str = typer.Option(
        "",  # Default value of comamand
        help=f"Type of Snyk Open Source projects to apply tags to (default:all): {scatypes}",
    ),
):
    type = (
        [
            "maven",
            "npm",
            "nuget",
            "gradle",
            "pip",
            "yarn",
            "gomodules",
            "rubygems",
            "composer",
            "sbt",
            "golangdep",
            "cocoapods",
            "poetry",
            "govendor",
            "cpp",
            "yarn-workspace",
            "hex",
            "paket",
            "golang",
        ]
        if scaType is None or scaType == ""
        else [scaType]
    )
    orgs = (
        get_org_ids(snyktkn, group_id, tenant)
        if org_id is None or org_id == ""
        else [org_id]
    )
    typer.secho(
        f"\nAdding the OpenSource tag to {scaType} projects in Snyk for easy filtering via the UI",
        bold=True,
    )
    apply_tags_to_projects(
        snyktkn,
        orgs,
        type,
        tag="OpenSource",
        key="Product",
        tenant=tenant,
        addprojecttype=addprojecttype,
    )


# Container Command
containertypes = typer.style(
    "\n dockerfile\n apk\n deb\n rpm\n linux", bold=True, fg=typer.colors.MAGENTA
)


@app.command(help="Apply Container tag to Snyk Container projects - Product:Container")
def container(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        help="Group ID of the Snyk Group you want to apply the tags to",
        envvar=["GROUP_ID"],
    ),
    org_id: str = typer.Option(
        "",  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify one Organization ID to only apply the tag to one organization",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    containerType: str = typer.Option(
        "",  # Default value of comamand
        help=f"Type of Snyk Container projects to apply tags to (default:all): {containertypes}",
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    addprojecttype: bool = typer.Option(
        False,
        "--addprojecttype",  # Default value of comamand
        help=f"Add an additional tag that will cover the project type e.g. Type:dockerfile (default is false), use --addprojecttype to turn into True.",
    ),
):
    type = (
        ["dockerfile", "apk", "deb", "rpm", "linux"]
        if containerType is None or containerType == ""
        else [containerType]
    )
    orgs = (
        get_org_ids(snyktkn, group_id, tenant)
        if org_id is None or org_id == ""
        else [org_id]
    )
    typer.secho(
        f"\nAdding the Container tag to {containerType} projects in Snyk for easy filtering via the UI",
        bold=True,
    )
    apply_tags_to_projects(
        snyktkn,
        orgs,
        type,
        tag="Container",
        key="Product",
        tenant=tenant,
        addprojecttype=addprojecttype,
    )


# Custom Command
@app.command(help="Apply custom tags to the preferred project type")
def custom(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        help="Group ID of the Snyk Group you want to apply the tags to",
        envvar=["GROUP_ID"],
    ),
    org_id: str = typer.Option(
        "",  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify one Organization ID to only apply the tag to one organization",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    projectType: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Type of Snyk project to apply tags to (choose one): {sasttypes}, {containertypes}, {scatypes}, {iactypes}",
    ),
    tagKey: str = typer.Option(
        ..., help="Tag key: identifier of the tag"  # Default value of comamand
    ),
    tagValue: str = typer.Option(
        ..., help="Tag value: value of the tag"  # Default value of comamand
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    addprojecttype: bool = typer.Option(
        False,
        "--addprojecttype",  # Default value of comamand
        help=f"Add an additional tag that will cover the project type e.g. Type:dockerfile (default is false), use --addprojecttype to turn into True.",
    ),
):
    typer.secho(
        f"\nAdding the tag key {tagKey} and tag value {tagValue} to {projectType} projects in Snyk for easy filtering via the UI",
        bold=True,
    )

    type = []
    type.append(projectType)
    orgs = (
        get_org_ids(snyktkn, group_id, tenant)
        if org_id is None or org_id == ""
        else [org_id]
    )
    apply_tags_to_projects(
        snyktkn,
        orgs,
        type,
        tagValue,
        tagKey,
        tenant=tenant,
        addprojecttype=addprojecttype,
    )


# alltargets Command
@app.command(
    help="Apply tags at all targets on projects containing a common shared name"
)
def alltargets(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        help="Group ID of the Snyk Group you want to apply the tags to",
        envvar=["GROUP_ID"],
    ),
    org_id: str = typer.Option(
        "",  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify one Organization ID to only apply the tag to one organization",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    contains_name: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Common name substring shared by projects to apply tags to",
    ),
    name_ignorecase: bool = typer.Option(
        False,
        "--name-ignorecase",  # Default value of comamand
        help=f"name case-sensitive, use --name-ignorecase to perform case-insensitive matching.",
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    tagKey: str = typer.Option(
        ..., help="Tag key: identifier of the tag"  # Default value of comamand
    ),
    tagValue: str = typer.Option(
        ..., help="Tag value: value of the tag"  # Default value of comamand
    ),
):
    typer.secho(
        f"\nAdding the tag key {tagKey} and tag value {tagValue} to {contains_name} projects in Snyk for easy filtering via the UI",
        bold=True,
    )

    orgs = (
        get_org_ids(snyktkn, group_id, tenant)
        if org_id is None or org_id == ""
        else [org_id]
    )
    apply_tags_to_projects_by_name(
        snyktkn,
        orgs,
        contains_name,
        name_ignorecase,
        tagValue,
        tagKey,
        tenant=tenant,
    )
