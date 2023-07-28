import re


def object_matcher(obj: dict, context: dict):
    for k, v in obj.items():
        if isinstance(v, str):
            return prop_string_matcher(k, v, context)
        if isinstance(v, dict):
            if "regex" in v:
                return prop_regex_matcher(k, v["regex"], context)
            else:
                return prop_object_matcher(k, v, context)


def prop_string_matcher(k: str, v: str, context: dict):
    def match_fn(obj: dict) -> bool:
        return obj.get(k) == v

    return match_fn


def prop_regex_matcher(k: str, v: str, context: dict):
    pattern = re.compile(v)

    def match_fn(obj: dict) -> bool:
        prop_val = obj.get(k)
        if not prop_val or not isinstance(prop_val, str):
            return False
        m = pattern.search(prop_val)
        if not m:
            return False
        context.update(**m.groupdict())
        return True

    return match_fn


def prop_object_matcher(k: str, v: dict, context: dict):
    prop_matcher = object_matcher(v, context)

    def match_fn(obj: dict) -> bool:
        prop_obj = obj.get(k)
        if not prop_obj or not isinstance(prop_obj, dict):
            return False
        return prop_matcher(prop_obj)

    return match_fn
