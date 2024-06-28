import json
import subprocess
import yaml

from unittest import TestCase

from .helpers import FAKE_LEAKS_PATH
from .helpers import GITLEAKS_PATTERNS_PATH
from .helpers import TESTDATA_PATH
from .helpers import sort_results

VERSION = "7.6.1"
PATTERNS_PATH = GITLEAKS_PATTERNS_PATH / VERSION
EXPECTED_RESULTS_PATH = TESTDATA_PATH / "gitleaks-7.6.1-results.yaml"


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
        )

        # Make sure it exits like it should
        self.assertEqual(leaks_exit_code, completed_process.returncode)

        actual = sort_results(
            [json.loads(line) for line in completed_process.stdout.splitlines()]
        )

        with open(EXPECTED_RESULTS_PATH, "r", encoding="UTF-8") as expected_file:
            expected = sort_results(yaml.load(expected_file, Loader=yaml.SafeLoader))

        # Check the results
        for i, expected_result in enumerate(expected):
            self.assertDictEqual(
                expected_result,
                # Only check the keys covered in expected
                {key: actual[i][key] for key in expected_result if key in actual[i]},
                f"testing item {i}",
            )

        # Make sure none were missed
        self.assertEqual(len(expected), len(actual))
