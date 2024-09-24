import json
import subprocess
import yaml

from unittest import TestCase

from .helpers import FAKE_LEAKS_PATH
from .helpers import TESTDATA_PATH
from .helpers import assert_equal_results

EXPECTED_RESULTS_PATH = TESTDATA_PATH / "leaktk-scanner-results.yaml"
CONFIG_PATH = TESTDATA_PATH / "leaktk-scanner-config.toml"


class TestLeakTKScanner(TestCase):
    maxDiff = 10000

    def test_patterns(self):
        """
        Run leaktk-scanner against the general test contents using the latest patterns
        """
        completed_process = subprocess.run(
            [
                f"leaktk-scanner",
                "scan",
                "--id=test-scan",
                "--kind=Files",
                f"--config={CONFIG_PATH}",
                f"--resource={FAKE_LEAKS_PATH}",
            ],
            capture_output=True,
            check=False,
            encoding="UTF-8",
        )

        # Make sure it exits like it should
        self.assertEqual(
            0,
            completed_process.returncode,
            f"\n\nSTDERR:\n\n{completed_process.stderr}",
        )

        # Load the response
        response = json.loads(completed_process.stdout)
        # Spot check that we got the right response back
        self.assertEqual(response["request_id"], "test-scan")

        # Generate the results
        actual = [
            {  # Flatten results for easier testing
                "rule.description": r["rule"]["description"],
                "rule.id": r["rule"]["id"],
                "location.path": r["location"]["path"],
                "match": r["match"],
                "secret": r["secret"],
            }
            for r in response["results"]
        ]

        # Open up the testdata with expected results
        with open(EXPECTED_RESULTS_PATH, "r", encoding="UTF-8") as expected_file:
            expected = yaml.load(expected_file, Loader=yaml.SafeLoader)

        assert_equal_results(self, expected, actual)
