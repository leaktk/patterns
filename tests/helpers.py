from pathlib import Path

TESTS_PATH = Path(__file__).resolve().parent
TESTDATA_PATH = TESTS_PATH.parent / "testdata"
FAKE_LEAKS_PATH = TESTS_PATH.parent / "fake-leaks"
GITLEAKS_PATTERNS_PATH = TESTS_PATH.parent / "target" / "patterns" / "gitleaks"
