#! /usr/bin/env python3

import csv
from enum import Enum
import json
import logging
import sys

import typer
from rich import print as rich_print

from snyk_tags import __app_name__, __version__
from snyk_tags.lib.api import Api
from snyk_tags.lib.component.rules import parse_rules, project_matcher

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
)

app = typer.Typer()


class FormatType(str, Enum):
    log = "log"
    csv = "csv"
    json = "json"


class CsvFormatter:
    def __init__(self):
        self.wrote_header = False
        self.w = csv.writer(sys.stdout)

    def print(
        self,
        action: str,
        component: str,
        dry_run: bool,
        exclusive: bool,
        remove: bool,
        project: any,
    ):
        if not self.wrote_header:
            self.w.writerow(
                [
                    "action",
                    "mode",
                    "component",
                    "project.id",
                    "project.name",
                    "project.origin",
                    "project.target.display_name",
                    "project.target.url",
                    "project.target_reference",
                ]
            )
            self.wrote_header = True
        self.w.writerow(
            [
                "{}{}".format(dry_run and "would " or "", action),
                "{}{}".format(
                    remove and "remove" or "add",
                    exclusive and " exclusive" or "",
                ),
                component,
                project.get("id"),
                project.get("name"),
                project.get("origin"),
                project.get("target", {}).get("display_name"),
                project.get("target", {}).get("url"),
                project.get("target_reference"),
            ]
        )
        sys.stdout.flush()


class JsonFormatter:
    def print(
        self,
        action: str,
        component: str,
        dry_run: bool,
        exclusive: bool,
        remove: bool,
        project: any,
    ):
        print(
            json.dumps(
                {
                    "action": "{}{}".format(dry_run and "would " or "", action),
                    "mode": "{}{}".format(
                        remove and "remove" or "add",
                        exclusive and " exclusive" or "",
                    ),
                    "component": component,
                    "project": project,
                }
            )
        )


class LogFormatter:
    def print(
        self,
        action: str,
        component: str,
        dry_run: bool,
        exclusive: bool,
        remove: bool,
        project: any,
    ):
        rich_print(
            f"""{'{}{}'.format(dry_run and "would " or "", action)
                } "component:{component}" in project id="{project["id"]}" name="{project["name"]}\""""
        )


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
    format: FormatType = typer.Option(
        default=FormatType.log,
        help="Output format, one of: log, csv, json",
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
):
    if format == "csv":
        fmtr = CsvFormatter()
    elif format == "json":
        fmtr = JsonFormatter()
    else:
        fmtr = LogFormatter()

    with open(rules, "r") as f:
        rules_doc = parse_rules(f)
        (match_fn, context) = project_matcher(rules_doc)
        client = Api(
            snyktkn,
            v1_url=(
                f"https://api.{tenant}.snyk.io/v1"
                if tenant in ["eu", "au"]
                else "https://api.snyk.io/v1"
            ),
            rest_url=(
                f"https://api.{tenant}.snyk.io/rest"
                if tenant in ["eu", "au"]
                else "https://api.snyk.io/rest"
            ),
        )
        for project in client.org_projects(org_id):
            # Extract and transform project and target data from API response
            # for rule input. Rules operate over project attributes, extended
            # with a "target" object property derived from the related target's
            # attributes.
            project_obj = {"id": project["id"]}
            project_obj.update(**project.get("attributes", {}))

            target = (
                project.get("relationships", {})
                .get("target", {})
                .get("data", {})
                .get("attributes")
            )
            if target:
                project_obj.update(target=target)

            # Clear context as this dict is (re)used in-place with each
            # execution of the project matcher rules.
            context.clear()
            component = match_fn(project_obj)
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

            print_format_args = {
                "dry_run": dry_run,
                "exclusive": exclusive,
                "remove": remove,
                "project": project_obj,
            }

            if exclusive:
                for other_component in other_component_tags:
                    fmtr.print(
                        action="remove other tag",
                        component=other_component,
                        **print_format_args,
                    )
                    if not dry_run:
                        client.remove_project_tag(
                            org_id,
                            project["id"],
                            tag={"key": "component", "value": other_component},
                        )

            if remove:
                if have_component_tag:
                    fmtr.print(
                        action="remove tag", component=component, **print_format_args
                    )
                    if not dry_run:
                        client.remove_project_tag(
                            org_id,
                            project["id"],
                            tag={"key": "component", "value": component},
                        )
            else:
                if not have_component_tag:
                    fmtr.print(
                        action="add tag", component=component, **print_format_args
                    )
                    if not dry_run:
                        client.add_project_tag(
                            org_id,
                            project["id"],
                            tag={"key": "component", "value": component},
                        )
                else:
                    fmtr.print(
                        action="keep tag", component=component, **print_format_args
                    )
