#! /usr/bin/env python3

import logging
import httpx
import typer
from rich import print

from snyk_tags import __app_name__, __version__
from snyk_tags.lib.api import Api
from snyk_tags.lib.component_rules import parse_rules, project_matcher

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

app = typer.Typer()


@app.command(help=f"Manage software component project tags")
def tag(
    rules: str = typer.Argument(...),
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
    dry_run: bool = typer.Option(
        default=False,
        help="Dry run",
    ),
    remove: bool = typer.Option(
        default=False,
        help="Remove matching component tags defined by rules",
    ),
    exclusive: bool = typer.Option(
        default=False,
        help="Remove all other component tags from projects. When used in combination with --remove, all component tags are removed from matching projects.",
    ),
):
    with open(rules, "r") as f:
        rules_doc = parse_rules(f)
        (match_fn, context) = project_matcher(rules_doc)
        client = Api(snyktkn)
        for project in client.org_projects(org_id):
            # Extract and transform project and target data from API response
            # for rule input. Rules operate over project attributes, extended
            # with a "target" object property derived from the related target's
            # attributes.
            project_obj = {}
            project_obj.update(**project.get("attributes", {}))
            target = (
                project.get("relationships", {}).get("target", {}).get("attributes")
            )
            if target:
                project_obj.update(target=target)

            # Clear context as this dict is (re)used in-place with each
            # execution of the project matcher rules.
            context.clear()
            component = match_fn(project.get("attributes", {}))
            if not component:
                # Rule did not match
                continue

            # Interpolate matcher context values, if any were extracted
            component = component.format(**context)

            have_component_tag = any(
                tag.get("value")
                for tag in project.get("attributes", {}).get("tags", [])
                if tag.get("key") == "component" and tag.get("value") == component
            )
            other_component_tags = set(
                tag.get("value")
                for tag in project.get("attributes", {}).get("tags", [])
                if tag.get("key") == "component" and tag.get("value") != component
            )

            if exclusive:
                for other_component in other_component_tags:
                    print(
                        f"""{dry_run and "would remove" or "removing"} other tag "component:{other_component}" from project id="{project["id"]}" name="{project_obj["name"]}" (exclusive)"""
                    )
                    client.remove_project_tag(
                        org_id,
                        project["id"],
                        tag={"key": "component", "value": other_component},
                    )

            if remove:
                if have_component_tag:
                    print(
                        f"""{dry_run and "would remove" or "removing"} tag "component:{component}" from project id="{project["id"]}" name="{project_obj["name"]}\""""
                    )
                    client.remove_project_tag(
                        org_id,
                        project["id"],
                        tag={"key": "component", "value": component},
                    )
            else:
                if not have_component_tag:
                    print(
                        f"""{dry_run and "would add" or "adding"} tag "component:{component}" to project id="{project["id"]}" name="{project_obj["name"]}\""""
                    )
                    client.add_project_tag(
                        org_id,
                        project["id"],
                        tag={"key": "component", "value": component},
                    )
                else:
                    print(
                        f"""tag "component:{component}" already present on project id="{project["id"]}" name="{project_obj["name"]}\""""
                    )
