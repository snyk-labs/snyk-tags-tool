#! /usr/bin/env python3
import logging
import re

import httpx
import typer
from rich import print
from snyk import SnykClient

app = typer.Typer()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

logging.getLogger("httpx").setLevel(logging.WARNING)


# Remove tags from a specific project
def remove_tag_from_project(
    token: str,
    org_id: str,
    project_id: str,
    tag: str,
    key: str,
    project_name: str,
    tenant: str,
) -> tuple:
    base_url = (
        f"https://api.{tenant}.snyk.io/v1"
        if tenant in ["eu", "au"]
        else "https://api.snyk.io/v1"
    )
    client = SnykClient(token=token, url=base_url)
    try:
        client.organizations.get(org_id).projects.get(project_id).tags.delete(key, tag)
        print(f"Removing tag {key}:{tag} from {project_name}")
    except Exception as e:
        if "422" in str(e):
            print(
                f"The tag {key}:{tag} has already been removed from Project: {project_name}"
            )
        elif "404" in str(e):
            print((f"Project not found. Project: {project_name}. Error message: {e}."))
        else:
            print(f"Unknown error {e}")


# Remove tag loop with pysnyk
def remove_tags_from_projects(
    token: str, org_id: list, name: str, tag: str, key: str, tenant: str
) -> None:
    base_url = (
        f"https://api.{tenant}.snyk.io/rest"
        if tenant in ["eu", "au"]
        else "https://api.snyk.io/rest"
    )
    client_v3 = SnykClient(token=token, url=base_url, version="2023-08-31~experimental")
    params = {"limit": 100}
    projects = client_v3.get_rest_pages(f"/orgs/{org_id}/projects", params=params)

    isname = 0
    for project in projects:
        if project["attributes"]["name"].startswith(name):
            remove_tag_from_project(
                token=token,
                org_id=org_id,
                project_id=project["id"],
                tag=tag,
                key=key,
                tenant=tenant,
                project_name=project["attributes"]["name"],
            )
        else:
            isname = 1
    if isname == 1:
        print(
            f"[bold red]{name}[/bold red] is not a valid target, please check it is a target within the organization e.g. [bold blue]snyk-labs/snyk-goof[/bold blue]"
        )


def remove_tags_from_projects_by_name(
    token: str,
    org_id: str,
    name: str,
    ignorecase: bool,
    tag: str,
    key: str,
    tenant: str,
) -> None:
    exp = name.replace("\\", "\\\\") + "+"
    p = re.compile(exp, re.IGNORECASE) if ignorecase else re.compile(exp)
    base_url = (
        f"https://api.{tenant}.snyk.io/rest"
        if tenant in ["eu", "au"]
        else "https://api.snyk.io/rest"
    )
    client_v3 = SnykClient(token=token, url=base_url, version="2023-08-31~experimental")
    params = {"limit": 100}
    projects = client_v3.get_rest_pages(f"/orgs/{org_id}/projects", params=params)

    for project in projects:
        if p.search(project["attributes"]["name"]):
            remove_tag_from_project(
                token=token,
                org_id=org_id,
                project_id=project["id"],
                tag=tag,
                key=key,
                project_name=project["attributes"]["name"],
                tenant=tenant,
            )


# Reach to the API and generate tokens
def create_client(token: str, tenant: str) -> httpx.Client:
    base_url = (
        f"https://api.{tenant}.snyk.io/v1"
        if tenant in ["eu", "au"]
        else "https://api.snyk.io/v1"
    )
    headers = {"Authorization": f"token {token}"}
    return httpx.Client(base_url=base_url, headers=headers)


# Apply tags to a specific project
def remove_tag_from_group(
    token: str, group_id: str, force: bool, tag: str, key: str, tenant: str
) -> tuple:
    if force is True:
        tag_data = {"key": key, "value": tag, "force": force}
    else:
        tag_data = {"key": key, "value": tag}

    with create_client(token=token, tenant=tenant) as client:
        req = client.post(f"group/{group_id}/tags/delete", data=tag_data, timeout=None)
        group = client.get(f"group/{group_id}/orgs").json()
        group_name = group["name"]

        if req.status_code == 200:
            print(f"Successfully removed {key}:{tag} from Group: {group_name}")
        elif req.status_code == 403:
            print(
                f"The tag {key}:{tag} has entities attached in Group: {group_name}  Error message: {req.json()}"
            )
        elif req.status_code == 422:
            print(
                f"The tag {key}:{tag} has already been removed from Group: {group_name}  Error message: {req.json()}"
            )
        elif req.status_code == 404:
            print(
                f"Tag {key}:{tag} not found in {group_name}. Error message: {req.json()}."
            )
        return req.status_code, req.json()


repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)


@app.command(help=f"Remove a tag from a target, for example {repoexample}")
def tag_from_target(
    org_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify the Organization ID to remove the tag from",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    target: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Name of the target, for example {repoexample}",
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
):
    typer.secho(
        f"\nRemoving {tagKey}:{tagValue} from projects within {target}", bold=True
    )
    remove_tags_from_projects(snyktkn, org_id, target, tagValue, tagKey, tenant)


@app.command(
    help=f"Remove a tag from all targets, on projects containing a common shared name"
)
def tag_from_alltargets(
    org_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify the Organization ID to remove the tag from",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    contains_name: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Common name substring shared by projects to remove tags",
    ),
    name_ignorecase: bool = typer.Option(
        False,
        "--name-ignorecase",  # Default value of comamand
        help=f"name case-sensitive, use --name-ignorecase to perform case-insensitive matching.",
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
):
    typer.secho(
        f"\nRemoving {tagKey}:{tagValue} from projects within {org_id}", bold=True
    )
    remove_tags_from_projects_by_name(
        snyktkn, org_id, contains_name, name_ignorecase, tagValue, tagKey, tenant
    )


@app.command(help=f"Remove a tag from a Group, this can be forced through --force")
def tag_from_group(
    group_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["GROUP_ID"],
        help="Specify the Group where you want to remove the tag from",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with Group admin access",
        envvar=["SNYK_TOKEN"],
    ),
    force: bool = typer.Option(
        False,
        "--force",  # Default value of comamand
        help=f"Force delete tag that has entities (default is false), use --force to turn into True.",
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
):
    typer.secho(f"\nRemoving {tagKey}:{tagValue} from Group ID: {group_id}", bold=True)
    remove_tag_from_group(snyktkn, group_id, force, tagValue, tagKey, tenant)
