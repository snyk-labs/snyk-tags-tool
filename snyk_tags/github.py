#! /usr/bin/env python3

import logging
import re

import httpx
import typer
import validators
from github import Github
from github import Auth
from rich import print
from snyk import SnykClient

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
    elif req.status_code == 422:
        logging.warning(
            f"Tag {key}:{tag} is already applied for Project: {project_name}."
        )
    elif req.status_code == 404:
        logging.error(
            f"Project not found, likely a READ-ONLY project. Project: {project_name}. Error message: {req.json()}."
        )
    return req.status_code, req.json()


def validate_gh_url(url: str) -> str:
    validated_url = "invalid_gh_base_url"
    if validators.url(url):
        validated_url = url
    return validated_url


# GitHub Tagging Loop
def apply_github_owner_to_repo(
    snyktoken: str,
    org_ids: list,
    name: str,
    githubtoken: str,
    tenant: str,
    gh_base_url: str,
) -> None:
    ghauth = Auth.Token(githubtoken)
    g = Github(base_url=gh_base_url, auth=ghauth)
    with create_client(token=snyktoken, tenant=tenant) as client:
        for org_id in org_ids:
            base_url = (
                f"https://api.{tenant}.snyk.io/rest"
                if tenant in ["eu", "au"]
                else "https://api.snyk.io/rest"
            )
            client_v3 = SnykClient(
                token=snyktoken, url=base_url, version="2023-08-31~experimental"
            )
            params = {"limit": 100}
            projects = client_v3.get_rest_pages(
                f"/orgs/{org_id}/projects", params=params
            )

            badname = 0
            rightname = 0
            for project in projects:
                if project["attributes"]["name"].startswith(name + "(") or project[
                    "attributes"
                ]["name"].startswith(name + ":"):
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
                                                project_id=project["id"],
                                                tag=owner,
                                                key="Owner",
                                                project_name=project["attributes"][
                                                    "name"
                                                ],
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
    snyktoken: str,
    org_ids: list,
    name: str,
    githubtoken: str,
    tenant: str,
    gh_base_url: str,
) -> None:
    ghauth = Auth.Token(githubtoken)
    g = Github(base_url=gh_base_url, auth=ghauth)
    with create_client(token=snyktoken, tenant=tenant) as client:
        for org_id in org_ids:
            base_url = (
                f"https://api.{tenant}.snyk.io/rest"
                if tenant in ["eu", "au"]
                else "https://api.snyk.io/rest"
            )
            client_v3 = SnykClient(
                token=snyktoken, url=base_url, version="2023-08-31~experimental"
            )
            params = {"limit": 100}
            projects = client_v3.get_rest_pages(
                f"/orgs/{org_id}/projects", params=params
            )

            badname = 0
            rightname = 0
            for project in projects:
                if project["attributes"]["name"].startswith(name + "(") or project[
                    "attributes"
                ]["name"].startswith(name + ":"):
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
                                project_id=project["id"],
                                tag=topic,
                                key="GitHubTopic",
                                project_name=project["attributes"]["name"],
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
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    gh_base_url: str = typer.Option(
        "https://api.github.com",
        help=f"Base URL of Github instance (e.g. https://ghe.internal/api/v3). Defaults to https://api.github.com (Github.com)",
    ),
):
    typer.secho(
        f"\nAdding the Owner tag to projects within {target} for easy filtering via the UI",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
    gh_base_url = validate_gh_url(gh_base_url)
    apply_github_owner_to_repo(
        snyktkn, [org_id], target, githubtkn, tenant=tenant, gh_base_url=gh_base_url
    )


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
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
    gh_base_url: str = typer.Option(
        "https://api.github.com",
        help=f"Base URL of Github instance (e.g. https://ghe.internal/api/v3). Defaults to https://api.github.com (Github.com)",
    ),
):
    typer.secho(
        f"\nAdding the GitHubTopic tag to projects within {target} for easy filtering via the UI",
        bold=True,
        fg=typer.colors.MAGENTA,
    )
    gh_base_url = validate_gh_url(gh_base_url)
    apply_github_topics_to_repo(
        snyktkn, [org_id], target, githubtkn, tenant=tenant, gh_base_url=gh_base_url
    )
