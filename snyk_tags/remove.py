#! /usr/bin/env python3
import typer
import httpx
from rich import print
from snyk import SnykClient

app = typer.Typer()

# Remove tags from a specific project
def remove_tag_from_project(
    token: str, org_id: str, project_id: str, tag: str, key: str, project_name: str
) -> tuple:
    
    client = SnykClient(token=token)
    try:
        client.organizations.get(org_id).projects.get(project_id).tags.delete(key, tag)
        print(f"Removing tag {key}:{tag} from {project_name}")
    except Exception as e:
        if "422" in str(e):
            print(f"The tag {key}:{tag} has already been removed from Project: {project_name}")
        elif "404" in str(e):
            print((f"Project not found. Project: {project_name}. Error message: {e}."))
        else:
            print(f"Unknown error {e}")
    
# Remove tag loop with pysnyk 
def remove_tags_from_projects(token: str, org_id: list, name: str, tag: str, key: str) -> None:
    client = SnykClient(token=token)
    projects = client.organizations.get(org_id).projects.all()
    for project in projects:
        if project.name.startswith(name):
            remove_tag_from_project(
                    token=token, org_id=org_id, project_id=project.id, tag=tag, key=key, project_name=project.name
                )

# Reach to the API and generate tokens
def create_client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://snyk.io/api/v1", headers={"Authorization": f"token {token}"}
    )

# Apply tags to a specific project
def remove_tag_from_group(
    token: str, group_id: str, force: bool, tag: str, key: str 
) -> tuple:

    if force is True:
        tag_data = {
            "key": key,
            "value": tag,
            "force" : force 
        }
    else: 
        tag_data = {
            "key": key,
            "value": tag
        }

    with create_client(token=token) as client:
        req = client.post(f"group/{group_id}/tags/delete", data=tag_data)
        group = client.get(f"group/{group_id}/orgs").json()
        group_name = group["name"]
    
        if req.status_code == 200:
            print(f"Successfully removed {key}:{tag} from Group: {group_name}")
        if req.status_code == 403:
            print(f"The tag {key}:{tag} has entities attached in Group: {group_name}  Error message: {req.json()}")
        if req.status_code == 422:
            print(f"The tag {key}:{tag} has already been removed from Group: {group_name}  Error message: {req.json()}")
        if req.status_code == 404:
            print(f"Tag {key}:{tag} not found in {group_name}. Error message: {req.json()}.")
        return req.status_code, req.json()

repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)

@app.command(help=f"Remove a tag from a target, for example {repoexample}")
def tag_from_target(org_id: str = typer.Option(
            ..., # Default value of comamand
            envvar=["ORG_ID"],
            help="Specify the Organization ID to remove the tag from"
        ),  snyktkn: str = typer.Option(
            ..., # Default value of comamand
            help="Snyk API token with org admin access",
            envvar=["SNYK_TOKEN"]
        ),  target: str = typer.Option(
            ..., # Default value of comamand
            help=f"Name of the target, for example {repoexample}"
        ),  tagKey: str = typer.Option(
            ..., # Default value of comamand
            help="Tag key: identifier of the tag"
        ),  tagValue: str = typer.Option(
            ..., # Default value of comamand
            help="Tag value: value of the tag"
        )
    ):
    typer.secho(f"\nRemoving {tagKey}:{tagValue} from projects within {target}", bold=True)
    remove_tags_from_projects(snyktkn,org_id, target, tagValue, tagKey)

@app.command(help=f"Remove a tag from a Group, this can be forced through --force")
def tag_from_group(group_id: str = typer.Option(
            ..., # Default value of comamand
            envvar=["GROUP_ID"],
            help="Specify the Group where you want to remove the tag from"
        ),  snyktkn: str = typer.Option(
            ..., # Default value of comamand
            help="Snyk API token with Group admin access",
            envvar=["SNYK_TOKEN"]
        ),  force: bool = typer.Option(
            False, "--force", # Default value of comamand
            help=f"Force delete tag that has entities (default is false), use --force to turn into True.",
        ),  tagKey: str = typer.Option(
            ..., # Default value of comamand
            help="Tag key: identifier of the tag"
        ),  tagValue: str = typer.Option(
            ..., # Default value of comamand
            help="Tag value: value of the tag"
        )
    ):
    typer.secho(f"\nRemoving {tagKey}:{tagValue} from Group ID: {group_id}", bold=True)
    remove_tag_from_group(snyktkn,group_id, force, tagValue, tagKey)