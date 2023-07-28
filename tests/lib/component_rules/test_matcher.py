from dataclasses import dataclass

from snyk_tags.lib.component.rules import model
from snyk_tags.lib.component.rules.matcher import object_matcher


def test_string_matcher():
    cfg = model.parse_rules(
        r"""
version: 1
rules:
  - name: specific-project
    projects:
      - target:
          url: 'http://github.com/snyk/repo1'
    component: pkg:github/snyk/something-completely-stringy
"""
    )
    context = {}
    match_fn = object_matcher(cfg["rules"][0]["projects"][0], context)

    @dataclass
    class TestCase:
        project: any
        match: bool

    testcases = [
        TestCase({}, False),
        TestCase({"target": "nope"}, False),
        TestCase({"target": {"url": "nope"}}, False),
        TestCase({"target": {"url": "http://github.com/snyk/repo1"}}, True),
    ]
    for testcase in testcases:
        is_match = match_fn(testcase.project)
        assert is_match == testcase.match


def test_regex_matcher():
    cfg = model.parse_rules(
        r"""
version: 1
rules:
  - name: specific-project
    projects:
      - name:
          regex: ':foo:'
    component: pkg:github/snyk/something-completely-fooey
"""
    )
    context = {}
    match_fn = object_matcher(cfg["rules"][0]["projects"][0], context)

    @dataclass
    class TestCase:
        project: any
        match: bool

    testcases = [
        TestCase({}, False),
        TestCase({"name": "nope"}, False),
        TestCase({"name": {"foo": "foo"}}, False),
        TestCase({"name": ":foo:bar"}, True),
        TestCase({"name": "bar:foo:"}, True),
    ]
    for testcase in testcases:
        is_match = match_fn(testcase.project)
        assert is_match == testcase.match

def test_regex_context_matcher():
    cfg = model.parse_rules(
        r"""
version: 1
rules:
  - name: specific-project
    projects:
      - name:
          regex: 'docker-image[|](?P<image>\w+):(?P<tag>\w+)$'
    component: pkg:github/snyk/something-completely-fooey
"""
    )
    context = {}
    match_fn = object_matcher(cfg["rules"][0]["projects"][0], context)
    is_match = match_fn({
      "name": "docker-image|postgres:14",
    })
    assert is_match == True
    assert context.get('image') == 'postgres'
    assert context.get('tag') == '14'
