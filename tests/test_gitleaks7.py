import json
import subprocess
import yaml

from unittest import TestCase

from .helpers import FAKE_LEAKS_PATH
from .helpers import GITLEAKS_PATTERNS_PATH
from .helpers import TESTDATA_PATH
from .helpers import assert_equal_results

VERSION = "7.6.1"
PATTERNS_PATH = GITLEAKS_PATTERNS_PATH / VERSION
EXPECTED_RESULTS_PATH = TESTDATA_PATH / f"gitleaks-{VERSION}-results.yaml"


class TestGitleaks(TestCase):
    maxDiff = 10000

    def test_patterns(self):
        """
        Run gitleaks against the general test contents using the latest patterns
        """
        leaks_exit_code = 42
        completed_process = subprocess.run(
            [
                f"gitleaks-{VERSION}",
                "--quiet",
                "--no-git",
                "--format=json",
                f"--leaks-exit-code={leaks_exit_code}",
                f"--config-path={PATTERNS_PATH}",
                f"--path={FAKE_LEAKS_PATH.name}",
            ],
            capture_output=True,
            check=False,
            # This makes the for paths match what it would be if you did
            # a scan from the root of this project. It makes it easier for
            # generating the expected results
            cwd=FAKE_LEAKS_PATH.parent,
            encoding="UTF-8",
        )

        # Make sure it exits detecting leaks. Note: `go run` always returns
        # an exit status of 1, but it prints out the exit status to stderr.
        self.assertIn(
            f"exit status {leaks_exit_code}",
            completed_process.stderr,
            f"\n\nSTDERR:\n\n{completed_process.stderr}",
        )

        actual = [
            {
                "rule": result["rule"],
                "file": result["file"],
                "offender": result["offender"],
                "line": result["line"],
            }
            for result in map(json.loads, completed_process.stdout.splitlines())
        ]

        with open(EXPECTED_RESULTS_PATH, "r", encoding="UTF-8") as expected_file:
            expected = yaml.load(expected_file, Loader=yaml.SafeLoader)

        assert_equal_results(self, expected, actual)
