import json
import subprocess
import yaml

from unittest import TestCase

from .helpers import FAKE_LEAKS_PATH
from .helpers import GITLEAKS_PATTERNS_PATH
from .helpers import TESTDATA_PATH

VERSION = "7.6.1"
PATTERNS_PATH = GITLEAKS_PATTERNS_PATH / VERSION
EXPECTED_RESULTS_PATH = TESTDATA_PATH / "gitleaks-7.6.1-results.yaml"


class TestGitLeaks(TestCase):
    maxDiff = 10000

    def test_patterns(self):
        """
        Run gitleaks against the general test contents using the latest patterns
        """
        completed_process = subprocess.run(
            [
                f"gitleaks-{VERSION}",
                "--quiet",
                "--no-git",
                "--format=json",
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

        def sort_results(results):
            """
            The order of the results need to match for both.
            """
            if not results:
                return results

            keys = list(sorted(results[0].keys()))
            return list(sorted(results, key=lambda r: tuple(map(r.get, keys))))

        actual = sort_results(
            [json.loads(line) for line in completed_process.stdout.splitlines()]
        )

        with open(EXPECTED_RESULTS_PATH, "r", encoding="UTF-8") as expected_file:
            expected = sort_results(yaml.load(expected_file, Loader=yaml.SafeLoader))

        for i, result in enumerate(expected):
            self.assertDictEqual(result, actual[i], f"testing item {i} in expected")
