import toml

from libpatterns.common import copy_if
from libpatterns.common import gitleaks

version = "8.16.2"


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
            copy_if(pattern, "regexTarget", allowlist, "regexTarget")
            copy_if(pattern, "paths", allowlist, "paths")
            copy_if(pattern, "stopwords", allowlist, "stopwords")
            gitleaks_config["allowlist"] = allowlist
        elif pattern["kind"] == "rule":
            rule = {}
            copy_if(pattern, "id", rule, "id")
            copy_if(pattern, "name", rule, "description")
            copy_if(pattern, "regex", rule, "regex")
            copy_if(pattern, "secretGroup", rule, "secretGroup")
            copy_if(pattern, "entropy", rule, "entropy")
            copy_if(pattern, "path", rule, "path")
            copy_if(pattern, "tags", rule, "tags")
            copy_if(pattern, "keywords", rule, "keywords")
            copy_if(pattern, "allowlist", rule, "allowlist")

            if "rules" not in gitleaks_config:
                gitleaks_config["rules"] = [rule]
            else:
                gitleaks_config["rules"].append(rule)

    return toml.dumps(gitleaks_config).encode("UTF-8")


def test(tests, config_path):
    with tempfile.TemporaryDirectory() as tmp_dir:
        write_examples(tests, tmp_dir.name)
        results = gitleaks(
            version,
            "detect",
            "--no-git",
            "--config",
            str(config_path),
            "--report-path",
            "/dev/stdout",
            "--report-format",
            "json",
            "--source",
            tmp_dir.name,
        )
