from pathlib import Path

import yaml

TESTS_PATH = Path(__file__).resolve().parent
TESTDATA_PATH = TESTS_PATH.parent / "testdata"
FAKE_LEAKS_PATH = TESTDATA_PATH / "fake-leaks"
GITLEAKS_PATTERNS_PATH = TESTS_PATH.parent / "target" / "patterns" / "gitleaks"


def str_presenter(dumper, data):
    """
    Display multi-line values using |-
    """
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")

    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, str_presenter)


def strip_meta(result):
    """
    Strip the __meta__ information from a result. It's not relevant for
    comparing matches. It's only there for adding additional notes and data.
    """
    return {k: v for k, v in result.items() if k != "__meta__"}


def assert_equal_results(tc, expected, actual):
    # Remove meta info from the test results
    expected = list(map(strip_meta, expected))

    # This is used to format the results
    output = {
        "Description": "Below are the results found in one list but not the other",
        "Only In Expected": [result for result in expected if result not in actual],
        "Only In Actual": [result for result in actual if result not in expected],
    }

    only_in_one = bool(output["Only In Expected"] or output["Only In Actual"])
    tc.assertFalse(
        only_in_one,
        "\n"
        + yaml.dump(
            output,
            sort_keys=False,
            default_flow_style=False,
            width=float("inf"),
        ),
    )
