import yaml
import jsonschema

from .matcher import object_matcher


project_rule_schema = {
    "type": "object",
    "properties": {
        "name": {"$ref": "#/$defs/MatcherRule"},
        "origin": {"$ref": "#/$defs/MatcherRule"},
        "target": {
            "type": "object",
            "properties": {
                "display_name": {"$ref": "#/$defs/MatcherRule"},
                "url": {"$ref": "#/$defs/MatcherRule"},
            },
        },
        "target_reference": {"$ref": "#/$defs/MatcherRule"},
    },
}

rule_schema = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "minLength": 1,
        },
        "projects": {
            "type": "array",
            "items": project_rule_schema,
            "minItems": 1,
            "uniqueItems": True,
        },
        "component": {
            "type": "string",
            "minLength": 1,
        },
    },
    "required": ["name", "projects", "component"],
    "additionalProperties": False,
}

schema = {
    "type": "object",
    "properties": {
        "version": {
            "type": "number",
            "default": 1,
        },
        "rules": {
            "type": "array",
            "items": rule_schema,
            "minItems": 1,
            "uniqueItems": True,
        },
    },
    "required": ["version", "rules"],
    "additionalProperties": False,
    "$defs": {
        "MatcherRule": {
            "oneOf": [
                {
                    "type": "string",
                    "minLength": 1,
                },
                {
                    "type": "object",
                    "properties": {
                        "regex": {
                            "type": "string",
                            "minLength": 1,
                        },
                    },
                    "required": ["regex"],
                },
            ],
        },
    },
}


def parse_rules(input):
    data = yaml.safe_load(input)
    jsonschema.validate(data, schema)
    return data


def project_matcher(data):
    context = {}
    rule_matchers = []
    for rule in data["rules"]:
        match_fns = [object_matcher(project, context) for project in rule["projects"]]
        rule_matchers.append((match_fns, rule["component"]))

    def match_fn(obj: dict) -> str:
        for project_match_fns, component in rule_matchers:
            if any([match_fn(obj) for match_fn in project_match_fns]):
                return component
        return None

    return (match_fn, context)
