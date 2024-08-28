#! /usr/bin/env python3
import typer
from pathlib import Path
from typing import List, Optional
import csv
from snyk_tags import collection, attribute, remove
from rich import print
import json

app = typer.Typer()
repoexample = typer.style("'snyk-labs/nodejs-goof'", bold=True, fg=typer.colors.MAGENTA)
tagexample = typer.style("org-id,target,key,value", bold=True, fg=typer.colors.MAGENTA)
attributesexample = typer.style(
    "org-id,target,criticality,environment,lifecycle",
    bold=True,
    fg=typer.colors.MAGENTA,
)
removetaggroupexample = typer.style("key,value", bold=True, fg=typer.colors.MAGENTA)
removetagtargetexample = typer.style(
    "org-id,target,key,value", bold=True, fg=typer.colors.MAGENTA
)


@app.command(
    help=f"Apply a custom tag from a .csv or .json to a target, for example {repoexample} \n\n The .csv or .json must be in the format {tagexample}"
)
def target_tag(
    file: List[Path] = typer.Option(
        ..., help=f".csv or .json file with the format {tagexample}"
    ),
    snyktkn: str = typer.Option(
        ..., help="Snyk API token with org admin access", envvar=["SNYK_TOKEN"]
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
):
    for path in file:
        filters = {}
        if path.is_file():
            openfile = open(path)
            if ".csv" in openfile.name:
                csvreader = csv.DictReader(openfile)
                for row in csvreader:
                    org_id = row.get("org-id")
                    target = row.get("target")
                    key = row.get("key")
                    value = row.get("value")
                    filters = {
                        attr: val
                        for attr, val in row.items()
                        if attr in ["target_reference", "origins", "types"]
                    }
                    typer.secho(
                        f"\nAdding the tag key {key} and tag value {value} to projects within {target} for easy filtering via the UI",
                        bold=True,
                    )
                    collection.apply_tags_to_projects(
                        snyktkn, [org_id], target, value, key, tenant, filters
                    )
                openfile.close()
            elif ".json" in openfile.name:
                jsonreader = json.load(openfile)
                for row in jsonreader:
                    org_id = row.get("org-id")
                    target = row.get("target")
                    key = row.get("key")
                    value = row.get("value")
                    filters = {
                        attr: val
                        for attr, val in row.items()
                        if attr in ["target_reference", "origins", "types"]
                    }
                    typer.secho(
                        f"\nAdding the tag key {key} and tag value {value} to projects within {target} for easy filtering via the UI",
                        bold=True,
                    )
                    collection.apply_tags_to_projects(
                        snyktkn, [org_id], target, value, key, tenant, filters
                    )
                openfile.close()
            else:
                print(
                    f"The file {openfile.name} is not valid, it must be either a .csv or a .json"
                )
                openfile.close()
        else:
            print(f"The file or path does not exist")


@app.command(
    help=f"Apply attributes from a .csv or .json to a target, for example {repoexample} \n\n The .csv or .json must be in the format {attributesexample}"
)
def target_attributes(
    file: List[Path] = typer.Option(
        ..., help=f".csv or .json file with the format {attributesexample}"
    ),
    snyktkn: str = typer.Option(
        ..., help="Snyk API token with org admin access", envvar=["SNYK_TOKEN"]
    ),
    tenant: str = typer.Option(
        "",  # Default value of comamand
        help=f"Defaults to US tenant, add 'eu' or 'au' to use EU or AU tenant, use --tenant to change tenant.",
    ),
):
    for path in file:
        if path.is_file():
            openfile = open(path)
            if ".csv" in openfile.name:
                csvreader = csv.DictReader(openfile)
                for row in csvreader:
                    org_id = row.get("org-id")
                    target = row.get("target")
                    criticality = row.get("criticality")
                    environment = row.get("environment")
                    lifecycle = row.get("lifecycle")
                    typer.secho(
                        f"\nAdding the attributes {criticality}, {environment} and {lifecycle} to projects within {target} for easy filtering via the UI",
                        bold=True,
                        fg=typer.colors.MAGENTA,
                    )
                    attribute.apply_attributes_to_projects(
                        snyktkn,
                        [org_id],
                        target,
                        [criticality],
                        [environment],
                        [lifecycle],
                        tenant,
                    )
                openfile.close()
            elif ".json" in openfile.name:
                jsonreader = json.load(openfile)
                for row in jsonreader:
                    org_id = row.get("org-id")
                    target = row.get("target")
                    criticality = row.get("criticality")
                    environment = row.get("environment")
                    lifecycle = row.get("lifecycle")
                    typer.secho(
                        f"\nAdding the attributes {criticality}, {environment} and {lifecycle} to projects within {target} for easy filtering via the UI",
                        bold=True,
                        fg=typer.colors.MAGENTA,
                    )
                    attribute.apply_attributes_to_projects(
                        snyktkn,
                        [org_id],
                        target,
                        [criticality],
                        [environment],
                        [lifecycle],
                        tenant,
                    )
                openfile.close()
            else:
                print(
                    f"The file {openfile.name} is not valid, it must be either a .csv or a .json"
                )
                openfile.close()
        else:
            print(f"The file or path does not exist")


@app.command(
    help=f"Remove tags from a Group with .csv or .json, this can be forced through --force"
)
def remove_tag_from_group(
    file: List[Path] = typer.Option(
        ..., help=f".csv or .json file with the format {removetaggroupexample}"
    ),
    group_id: str = typer.Option(
        ...,
        envvar=["GROUP_ID"],
        help="Specify the Group where you want to remove the tag from",
    ),
    snyktkn: str = typer.Option(
        ..., help="Snyk API token with Group admin access", envvar=["SNYK_TOKEN"]
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help=f"Force delete tag that has entities (default is false), use --force to turn into True.",
    ),
):
    for path in file:
        if path.is_file():
            openfile = open(path)
            if ".csv" in openfile.name:
                csvreader = csv.DictReader(openfile)
                for row in csvreader:
                    tagKey = row.get("key")
                    tagValue = row.get("value")
                    typer.secho(
                        f"\nRemoving {tagKey}:{tagValue} from Group ID: {group_id}",
                        bold=True,
                    )
                    remove.remove_tag_from_group(
                        snyktkn, group_id, force, tagValue, tagKey
                    )
                openfile.close()
            elif ".json" in openfile.name:
                jsonreader = json.load(openfile)
                for row in jsonreader:
                    tagKey = row.get("key")
                    tagValue = row.get("value")
                    typer.secho(
                        f"\nRemoving {tagKey}:{tagValue} from Group ID: {group_id}",
                        bold=True,
                    )
                    remove.remove_tag_from_group(
                        snyktkn, group_id, force, tagValue, tagKey
                    )
                openfile.close()
            else:
                print(
                    f"The file {openfile.name} is not valid, it must be either a .csv or a .json"
                )
                openfile.close()
        else:
            print(f"The file or path does not exist")


@app.command(
    help=f"Remove a tag from a target with .csv or .json, for example {repoexample}"
)
def remove_tag_from_target(
    file: List[Path] = typer.Option(
        ..., help=f".csv or .json file with the format {removetagtargetexample}"
    ),
    snyktkn: str = typer.Option(
        ..., help="Snyk API token with org admin access", envvar=["SNYK_TOKEN"]
    ),
):
    for path in file:
        if path.is_file():
            openfile = open(path)
            if ".csv" in openfile.name:
                csvreader = csv.DictReader(openfile)
                for row in csvreader:
                    org_id = row.get("org-id")
                    target = row.get("target")
                    key = row.get("key")
                    value = row.get("value")
                    typer.secho(
                        f"\nRemoving {key}:{value} from projects within {target}",
                        bold=True,
                    )
                    remove.remove_tags_from_projects(
                        snyktkn, org_id, target, value, key
                    )
                openfile.close()
            elif ".json" in openfile.name:
                jsonreader = json.load(openfile)
                for row in jsonreader:
                    org_id = row.get("org-id")
                    target = row.get("target")
                    key = row.get("key")
                    value = row.get("value")
                    typer.secho(
                        f"\nRemoving {key}:{value} from projects within {target}",
                        bold=True,
                    )
                    remove.remove_tags_from_projects(
                        snyktkn, org_id, target, value, key
                    )
                openfile.close()
            else:
                print(
                    f"The file {openfile.name} is not valid, it must be either a .csv or a .json"
                )
                openfile.close()
        else:
            print(f"The file or path does not exist")
