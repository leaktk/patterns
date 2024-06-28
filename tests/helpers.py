from pathlib import Path

TESTS_PATH = Path(__file__).resolve().parent
TESTDATA_PATH = TESTS_PATH.parent / "testdata"
FAKE_LEAKS_PATH = TESTS_PATH.parent / "fake-leaks"
GITLEAKS_PATTERNS_PATH = TESTS_PATH.parent / "target" / "patterns" / "gitleaks"


def sort_results(results):
    """
    The order of the results need to match for both.
    """
    return list(
        sorted(
            # Sort the items in the dict
            ({k: r[k] for k in sorted(r)} for r in results),
            # Sort by a tuple of the values
            key=lambda r: tuple(map(r.get, sorted(r))),
        )
    )
