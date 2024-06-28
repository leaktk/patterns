import json
import subprocess
import yaml

from unittest import TestCase

from .helpers import FAKE_LEAKS_PATH
from .helpers import TESTDATA_PATH
from .helpers import prep_results

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
        )

        # Make sure it exits like it should
        self.assertEqual(0, completed_process.returncode)

        # Load the response
        response = json.loads(completed_process.stdout)
        # Spot check that we got the right response back
        self.assertEqual(response["request"]["id"], "test-scan")
        self.assertEqual(response["request"]["kind"], "Files")

        # Generate the results
        actual = prep_results(
            "rule.id",
            (
                {  # Flatten results for easier testing
                    "location.path": r["location"]["path"],
                    "match": r["match"],
                    "rule.description": r["rule"]["description"],
                    "rule.id": r["rule"]["id"],
                    "secret": r["secret"],
                }
                for r in response["results"]
            ),
        )

        # Open up the testdata with expected results
        with open(EXPECTED_RESULTS_PATH, "r", encoding="UTF-8") as expected_file:
            expected = prep_results(
                "rule.id", yaml.load(expected_file, Loader=yaml.SafeLoader)
            )

        for group, expected_results in expected.items():
            actual_results = actual[group]

            # Check the results
            for i, expected_result in enumerate(expected_results):
                self.assertDictEqual(
                    expected_result,
                    # Only check the keys covered in expected
                    {
                        key: actual_results[i][key]
                        for key in expected_result
                        if key in actual_results[i]
                    },
                    f"testing item {i} in {group}",
                )

            # Make sure none were missed
            self.assertEqual(len(expected_results), len(actual_results))
