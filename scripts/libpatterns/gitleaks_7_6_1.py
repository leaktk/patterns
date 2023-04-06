import toml

from libpatterns.common import copy_if


def to_string(patterns):
    """
    Returns config from these patterns
    """
    gitleaks_config = {}

    for pattern in patterns:
        if pattern["kind"] == "allowlist":
            allowlist = {}
            copy_if(pattern, "name", allowlist, "description")
            copy_if(pattern, "regexes", allowlist, "regexes")
            copy_if(pattern, "paths", allowlist, "paths")
            gitleaks_config["allowlist"] = allowlist
        elif pattern["kind"] == "rule":
            rule = {}
            copy_if(pattern, "name", rule, "description")
            copy_if(pattern, "regex", rule, "regex")
            copy_if(pattern, "entropy", rule, "entropy")
            copy_if(pattern, "path", rule, "path")
            copy_if(pattern, "tags", rule, "tags")
            copy_if(pattern, "allowlist", rule, "allowlist")

            if "rules" not in gitleaks_config:
                gitleaks_config["rules"] = [rule]
            else:
                gitleaks_config["rules"].append(rule)

    return toml.dumps(gitleaks_config).encode("UTF-8")


def test(tests, output_path):
    pass
