#! /usr/bin/env python3

import logging
import re

import httpx
import typer
from github import Github
from rich import print
from snyk import SnykClient

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


# Apply tags to a specific project
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
        logging.info(f"Successfully added {tag_data} tags to Project: {project_name}.")
    if req.status_code == 422:
        logging.warning(
            f"Tag {key}:{tag} is already applied for Project: {project_name}."
        )
    if req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}."
        )
    return req.status_code, req.json()


# GitHub Tagging Loop
def apply_github_owner_to_repo(
    snyktoken: str, org_ids: list, name: str, githubtoken: str
) -> None:
    g = Github(githubtoken)
    with create_client(token=snyktoken) as client:
        for org_id in org_ids:
            client_v3 = SnykClient(token=snyktoken)
            projects = client_v3.organizations.get(org_id).projects.all()

            badname = 0
            rightname = 0
            for project in projects:
                if project.name.startswith(name + "(") or project.name.startswith(
                    name + ":"
                ):
                    repo = g.get_repo(name)
                    contents = [""]
                    while contents:
                        entries = repo.get_contents(contents.pop(0))
                        for file_content in entries:
                            if file_content.type == "dir":
                                contents.append(file_content.path)
                            elif "CODEOWNERS" in file_content.path:
                                decoded = file_content.decoded_content.decode("utf-8")
                                if "@" in decoded:
                                    lines = re.split("\n| ", decoded)
                                    for word in lines:
                                        owner = word
                                        if owner == "":
                                            pass
                                        elif owner[0] == "@":
                                            owner = owner[1:]
                                            apply_tag_to_project(
                                                client=client,
                                                org_id=org_id,
                                                project_id=project.id,
                                                tag=owner,
                                                key="Owner",
                                                project_name=project.name,
                                            )
                                else:
                                    print("Invalid CODEOWNERS file")
                                break
                    rightname = 1
                else:
                    badname = 1
            if badname == 1 and rightname == 0:
                print(
                    f"[bold red]{name}[/bold red] is not a valid target, please check it is a target within the organization e.g. [bold blue]snyk-labs/snyk-goof[/bold blue]"
                )


def apply_github_topics_to_repo(
    snyktoken: str, org_ids: list, name: str, githubtoken: str
) -> None:
    g = Github(githubtoken)
    with create_client(token=snyktoken) as client:
        for org_id in org_ids:
            client_v3 = SnykClient(token=snyktoken)
            projects = client_v3.organizations.get(org_id).projects.all()

            badname = 0
            rightname = 0
            for project in projects:
                if project.name.startswith(name + "(") or project.name.startswith(
                    name + ":"
                ):
                    repo = g.get_repo(name)
                    if repo.get_topics() == []:
                        print(
                            f"[bold red]{name}[/bold red] does not have valid topics, please check the repository has valid topics"
                        )
                        break
                    else:
                        for topic in repo.get_topics():
                            apply_tag_to_project(
                                client=client,
                                org_id=org_id,
                                project_id=project.id,
                                tag=topic,
                                key="GitHubTopic",
                                project_name=project.name,
                            )
                    rightname = 1
                else:
                    badname = 1
            if badname == 1 and rightname == 0:
                print(
                    f"[bold red]{name}[/bold red] is not a valid target, please check it is a target within the organization e.g. [bold blue]snyk-labs/snyk-goof[/bold blue]"
                )


repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)


# GitHub Code Owner Tagging
@app.command(
    help=f"Add the GitHub CODEOWNERS (only GitHub handles) as tags to the specified repo in Snyk, for example {repoexample}"
)
def owners(
    org_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify the Organization ID where you want to apply the tag",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    target: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Name of the repo, for example {repoexample}",
    ),
    githubtkn: str = typer.Option(
        ...,  # Default value of comamand
        help="GitHub Personal Access Token with access to the repository",
        envvar=["GITHUB_TOKEN"],
    ),
):
    typer.secho(
        f"\nAdding the Owner tag to projects within {target} for easy filtering via the UI",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
    apply_github_owner_to_repo(snyktkn, [org_id], target, githubtkn)


# GitHub Topics Tagging
@app.command(
    help=f"Add the GitHub repo's Topics as tags to the specified repo in Snyk, for example {repoexample}"
)
def topics(
    org_id: str = typer.Option(
        ...,  # Default value of comamand
        envvar=["ORG_ID"],
        help="Specify the Organization ID where you want to apply the tag",
    ),
    snyktkn: str = typer.Option(
        ...,  # Default value of comamand
        help="Snyk API token with org admin access",
        envvar=["SNYK_TOKEN"],
    ),
    target: str = typer.Option(
        ...,  # Default value of comamand
        help=f"Name of the repo, for example {repoexample}",
    ),
    githubtkn: str = typer.Option(
        ...,  # Default value of comamand
        help="GitHub Personal Access Token with access to the repository",
        envvar=["GITHUB_TOKEN"],
    ),
):
    typer.secho(
        f"\nAdding the GitHubTopic tag to projects within {target} for easy filtering via the UI",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
    apply_github_topics_to_repo(snyktkn, [org_id], target, githubtkn)
