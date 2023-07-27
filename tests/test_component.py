import os
import re

# Necessary to ensure consistent stdout contents from typer.
# Otherwise asserts below could fail due to terminal width!
os.environ["COLUMNS"] = "132"

import pytest
from typer.testing import CliRunner

from snyk_tags import tags

runner = CliRunner()
app = tags.app


@pytest.fixture
def assert_all_responses_were_requested() -> bool:
    return False


def test_component_tag_match_dry_run(tmpdir, httpx_mock):
    rules_file = tmpdir.join("rules.yaml")
    rules_file.write(
        """
version: 1
rules:
  - name: test
    projects:
      - name: test
    component: test-component
"""
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile("^.*/orgs/some-org/projects[?].*"),
        json={
            "data": [
                {
                    "id": "some-project",
                    "attributes": {
                        "name": "test",
                    },
                },
            ],
        },
    )
    httpx_mock.add_response(
        method="POST", url=re.compile("^.*/org/some-org/project/some-project/tags$")
    )
    httpx_mock.add_response(
        status_code=400
    )  # catch-all response, otherwise backoff retry will block testing

    result = runner.invoke(
        app,
        [
            "component",
            "tag",
            "--org-id",
            "some-org",
            "--snyktkn",
            "some-token",
            "--dry-run",
            str(rules_file),
        ],
    )
    assert result.exit_code == 0
    assert (
        """would add tag "component:test-component" to project id="some-project" name="test\""""
        in result.stdout
    )


def test_component_tag_match_added(tmpdir, httpx_mock):
    rules_file = tmpdir.join("rules.yaml")
    rules_file.write(
        """
version: 1
rules:
  - name: test
    projects:
      - name: test
    component: test-component
"""
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile("^.*/orgs/some-org/projects[?].*"),
        json={
            "data": [
                {
                    "id": "some-project",
                    "attributes": {
                        "name": "test",
                    },
                },
            ],
        },
    )
    httpx_mock.add_response(
        method="POST", url=re.compile("^.*/org/some-org/project/some-project/tags$")
    )
    httpx_mock.add_response(
        status_code=400
    )  # catch-all response, otherwise backoff retry will block testing

    result = runner.invoke(
        app,
        [
            "component",
            "tag",
            "--org-id",
            "some-org",
            "--snyktkn",
            "some-token",
            str(rules_file),
        ],
    )
    assert result.exit_code == 0
    assert (
        """adding tag "component:test-component" to project id="some-project" name="test\""""
        in result.stdout
    )


def test_component_tag_match_already_tagged(tmpdir, httpx_mock):
    rules_file = tmpdir.join("rules.yaml")
    rules_file.write(
        """
version: 1
rules:
  - name: test
    projects:
      - name: test
    component: test-component
"""
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile("^.*/orgs/some-org/projects[?].*"),
        json={
            "data": [
                {
                    "id": "some-project",
                    "attributes": {
                        "name": "test",
                        "tags": [{"key": "component", "value": "test-component"}],
                    },
                },
            ],
        },
    )
    httpx_mock.add_response(
        method="POST", url=re.compile("^.*/org/some-org/project/some-project/tags$")
    )
    httpx_mock.add_response(
        status_code=400
    )  # catch-all response, otherwise backoff retry will block testing

    result = runner.invoke(
        app,
        [
            "component",
            "tag",
            "--org-id",
            "some-org",
            "--snyktkn",
            "some-token",
            str(rules_file),
        ],
    )
    assert result.exit_code == 0
    assert (
        """tag "component:test-component" already present on project id="some-project" name="test\""""
        in result.stdout
    )


def test_component_tag_match_exclusive(tmpdir, httpx_mock):
    rules_file = tmpdir.join("rules.yaml")
    rules_file.write(
        """
version: 1
rules:
  - name: test
    projects:
      - name: test
    component: test-component
"""
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile("^.*/orgs/some-org/projects[?].*"),
        json={
            "data": [
                {
                    "id": "some-project",
                    "attributes": {
                        "name": "test",
                        "tags": [{"key": "component", "value": "other-component"}],
                    },
                },
            ],
        },
    )
    httpx_mock.add_response(
        method="POST", url=re.compile("^.*/org/some-org/project/some-project/tags$")
    )
    httpx_mock.add_response(
        method="POST",
        url=re.compile("^.*/org/some-org/project/some-project/tags/remove$"),
    )
    httpx_mock.add_response(
        status_code=400
    )  # catch-all response, otherwise backoff retry will block testing

    result = runner.invoke(
        app,
        [
            "component",
            "tag",
            "--org-id",
            "some-org",
            "--snyktkn",
            "some-token",
            "--exclusive",
            str(rules_file),
        ],
    )
    assert result.exit_code == 0
    print(result.stdout)
    assert (
        """removing other tag "component:other-component" from project id="some-project" name="test" (exclusive)"""
        in result.stdout
    )
    assert (
        """adding tag "component:test-component" to project id="some-project" name="test\""""
        in result.stdout
    )


def test_component_tag_match_remove(tmpdir, httpx_mock):
    rules_file = tmpdir.join("rules.yaml")
    rules_file.write(
        """
version: 1
rules:
  - name: test
    projects:
      - name: test
    component: test-component
"""
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile("^.*/orgs/some-org/projects[?].*"),
        json={
            "data": [
                {
                    "id": "some-project",
                    "attributes": {
                        "name": "test",
                        "tags": [
                            {"key": "component", "value": "other-component"},
                            {"key": "component", "value": "test-component"},
                        ],
                    },
                },
            ],
        },
    )
    httpx_mock.add_response(
        method="POST", url=re.compile("^.*/org/some-org/project/some-project/tags$")
    )
    httpx_mock.add_response(
        method="POST",
        url=re.compile("^.*/org/some-org/project/some-project/tags/remove$"),
    )
    httpx_mock.add_response(
        status_code=400
    )  # catch-all response, otherwise backoff retry will block testing

    result = runner.invoke(
        app,
        [
            "component",
            "tag",
            "--org-id",
            "some-org",
            "--snyktkn",
            "some-token",
            "--remove",
            str(rules_file),
        ],
    )
    assert result.exit_code == 0
    assert (
        """removing tag "component:test-component" from project id="some-project" name="test\""""
        in result.stdout
    )


def test_component_tag_match_remove_exclusive(tmpdir, httpx_mock):
    rules_file = tmpdir.join("rules.yaml")
    rules_file.write(
        """
version: 1
rules:
  - name: test
    projects:
      - name: test
    component: test-component
"""
    )
    httpx_mock.add_response(
        method="GET",
        url=re.compile("^.*/orgs/some-org/projects[?].*"),
        json={
            "data": [
                {
                    "id": "some-project",
                    "attributes": {
                        "name": "test",
                        "tags": [
                            {"key": "component", "value": "other-component"},
                            {"key": "component", "value": "test-component"},
                        ],
                    },
                },
            ],
        },
    )
    httpx_mock.add_response(
        method="POST", url=re.compile("^.*/org/some-org/project/some-project/tags$")
    )
    # Note there will be two tag remove calls
    httpx_mock.add_response(
        method="POST",
        url=re.compile("^.*/org/some-org/project/some-project/tags/remove$"),
    )
    httpx_mock.add_response(
        method="POST",
        url=re.compile("^.*/org/some-org/project/some-project/tags/remove$"),
    )
    httpx_mock.add_response(
        status_code=400
    )  # catch-all response, otherwise backoff retry will block testing

    result = runner.invoke(
        app,
        [
            "component",
            "tag",
            "--org-id",
            "some-org",
            "--snyktkn",
            "some-token",
            "--remove",
            "--exclusive",
            str(rules_file),
        ],
    )
    print(result.stdout)
    assert result.exit_code == 0
    assert (
        """removing other tag "component:other-component" from project id="some-project" name="test" (exclusive)"""
        in result.stdout
    )
    assert (
        """removing tag "component:test-component" from project id="some-project" name="test\""""
        in result.stdout
    )
