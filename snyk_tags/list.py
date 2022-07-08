#! /usr/bin/env python3
import typer

from snyk_tags import __app_name__, __version__

app = typer.Typer()

'''
List all the different project types for Snyk Products
'''

# SAST Command
@app.command(help="List all Snyk Code project types")
def sast():
    snykcmd = typer.style("snyk-tags apply sast", bold=True, fg=typer.colors.MAGENTA)
    typer.echo(f"These are all the Snyk Code project types you can use with {snykcmd}")
    typer.echo("\n sast")

# Container Command
@app.command(help="List all Snyk Container project types")
def container():
    snykcmd = typer.style("snyk-tags apply container", bold=True, fg=typer.colors.MAGENTA)
    typer.echo(f"These are all the Snyk Container project types you can use with {snykcmd}")
    typer.echo("\n dockerfile\n apk\n deb\n rpm\n linux")

# IaC Command
@app.command(help="List all Snyk IaC project types")
def iac():
    snykcmd = typer.style("snyk-tags apply iac", bold=True, fg=typer.colors.MAGENTA)
    typer.echo(f"These are all the Snyk IaC project types you can use with {snykcmd}")
    typer.echo("\n terraformconfig\n terraformplan\n k8sconfig\n helmconfig\n cloudformationconfig\n armconfig")

# SCA Command
@app.command(help="List all Snyk Open Source project types")
def sca():
    snykcmd = typer.style("snyk-tags apply sca", bold=True, fg=typer.colors.MAGENTA)
    typer.echo(f"These are all the Snyk Open Source project types you can use with {snykcmd}")
    typer.echo("\n maven\n npm\n nuget\n gradle\n pip\n yarn\n gomodules\n rubygems\n composer\n sbt\n golangdep\n cocoapods\n poetry\n govendor\n cpp\n yarn-workspace\n hex\n paket\n golang")