from pathlib import Path

TESTS_PATH = Path(__file__).resolve().parent
TESTDATA_PATH = TESTS_PATH.parent / "testdata"
FAKE_LEAKS_PATH = TESTS_PATH.parent / "fake-leaks"
GITLEAKS_PATTERNS_PATH = TESTS_PATH.parent / "target" / "patterns" / "gitleaks"


def prep_results(group_key, results):
    """
    Order and group the results for comparison
    """
    sorted_results = list(
        sorted(
            # Sort the items in the dict
            ({k: r[k] for k in sorted(r)} for r in results),
            # Sort by a tuple of the values
            key=lambda r: tuple(map(r.get, sorted(r))),
        )
    )

    grouped = {}
    for result in sorted_results:
        group_value = result[group_key]

        if group_value in grouped:
            grouped[group_value].append(result)
        else:
            grouped[group_value] = [result]

    return grouped
