"""
How to use these tests:

For mosts cases you should only have to edit the two data structures at the
top of the file here.

(Sometimes it is just as important to test what you are NOT matching against
as it is to test what you are matching against)

SHOULD_MATCH

Add an item to should match if should match. Use the format of the other
entries as a reference.

Fields:

"description" - the rule description that it's matching against
"example" - an example of the leak line
"offender" - what should be matched
"comment" - (optional) rational on why it's there
"filename" - (optional) if the rule matches a specific filename

SHOULD_NOT_MATCH

These items will also be added to the file but should not turn up in the
results

"example" - an example of the leak line
"comment" - (optional) rational on why it's there
"filename" - (optional) if the rule matches a specific filename
"""
import json
import subprocess
import shutil

from pathlib import Path
from unittest import TestCase

VERSION = "8.12.0"

SHOULD_MATCH = [
    # TODO: add these back as 8.12.0 patterns are added
]

SHOULD_NOT_MATCH = [
    # TODO: add these back as 8.12.0 patterns are added
]


class TestGitLeaks(TestCase):
    test_dir = Path(__file__).resolve().parent
    patterns_path = test_dir.joinpath(
        "..", "..", "..", "target", "patterns", "gitleaks", VERSION,
    )
    maxDiff = 10000

    def setUp(self):
        self.test_pattern_dir = Path(f"/tmp/leaktk-patterns-{VERSION}")

        # Start fresh
        if self.test_pattern_dir.is_dir():
            shutil.rmtree(self.test_pattern_dir)

        self.test_pattern_dir.mkdir(parents=True)

        # Write everything (including the specific ones) to the test file)
        general_test_file_path = self.test_pattern_dir.joinpath("general-test")
        with open(general_test_file_path, "w+") as general_test_file:
            general_test_file.write(
                "\n".join(
                    entry["example"]
                    for entry in SHOULD_NOT_MATCH + SHOULD_MATCH
                    if not "filename" in entry
                )
            )

        # Handle ones with custom filenames
        for entry in SHOULD_NOT_MATCH + SHOULD_MATCH:
            if "filename" not in entry:
                continue

            custom_file_path = self.test_pattern_dir.joinpath(entry["filename"])

            if not custom_file_path.parent.is_dir():
                custom_file_path.parent.mkdir(parents=True)

            with open(custom_file_path, "a+") as custom_file:
                custom_file.write(entry["example"] + "\n")

    # TODO: pending writing some patterns and tests
    # def test_patterns(self):
    #     """
    #     Run gitleaks against the general test contents using the latest patterns
    #     """
    #     completed_process = subprocess.run(
    #         [
    #             f"gitleaks-{VERSION}",
    #             "detect"
    #             "--no-git",
    #             "--report-format=json",
    #             "--report-path=/dev/stdout",
    #             f"--config={self.patterns_path}",
    #             f"--path={self.test_pattern_dir}",
    #         ],
    #         capture_output=True,
    #         check=False,
    #     )
    #     self.assertEqual(completed_process.stderr.decode("UTF-8"), "")

    #     raw_lines = completed_process.stdout.splitlines()
    #     leaks = [json.loads(line) for line in raw_lines]

    #     # These are the offenders found above. This will need to be updated
    #     # when adding a new item to test.
    #     matches = {(m["description"], m["offender"]) for m in SHOULD_MATCH}

    #     for leak in leaks:
    #         leak_key = (leak["rule"], leak["offender"])

    #         self.assertIn(leak_key, matches)
    #         matches.remove(leak_key)

    #     # Make sure everything's been accounted for
    #     self.assertEqual(matches, set())
