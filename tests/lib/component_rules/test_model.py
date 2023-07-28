from dataclasses import dataclass

import jsonschema
import pytest

from snyk_tags.lib.component.rules import model


def test_model_parse():
    m = model.parse_rules(r"""
version: 1
rules:
  - name: specific-project
    projects:
      - target:
          url: 'http://github.com/snyk/repo1'
      - target:
          url: 'http://github.com/snyk/repo2'
      - target:
          url: 'http://github.com/snyk/repo3'
      - origin: kubernetes
        target:
          display_name:
            regex: '.*/deployment\.apps/some-image$'
      - origin: ecr
        target:
          display_name:
            regex: '^some-image:[0-9a-f]+$'
      - origin: cli
        name:
          regex: '.*\.amazonaws\.com/some-image$'
    component: pkg:github/snyk/something-completely-different
""")
    assert m is not None
    assert m['version'] == 1
    assert m['rules'][0]['component'] == "pkg:github/snyk/something-completely-different"


def test_jsonschema_constraints():
    @dataclass
    class TestCase:
        match: str
        yaml: str
    testcases = [
        TestCase("'' is not of type 'object'", "''"),
        TestCase("Failed validating 'required' in schema", "{}"),
        TestCase("Failed validating 'minItems' in schema", """
version: 1
rules: []
"""),
        TestCase("Failed validating 'minLength' in schema", """
version: 1
rules:
  - name: foo
    projects:
      - name: ''
    component: 'bar'
"""),
        TestCase("'regex' is a required property", """
version: 1
rules:
  - name: foo
    projects:
      - target:
          url: {}
    component: 'baz'
"""),
    ]

    for testcase in testcases:
        with pytest.raises(jsonschema.ValidationError, match=testcase.match):
            model.parse_rules(testcase.yaml)
