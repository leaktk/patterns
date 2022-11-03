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

"RuleID" - the rule description that it's matching against
"Example" - an example of the leak line
"Secret" - what should be matched
"Comment" - (optional) rational on why it's there
"File" - (optional) if the rule matches a specific filename

SHOULD_NOT_MATCH

These items will also be added to the file but should not turn up in the
results

"Example" - an example of the leak line
"Comment" - (optional) rational on why it's there
"File" - (optional) if the rule matches a specific filename
"""
import json
import subprocess
import shutil

from pathlib import Path
from unittest import TestCase

VERSION = "8.12.0"

SHOULD_MATCH = [
    # Very WIP just here to unblock testing
    {
        "RuleID": "asymmetric-private-key",
        "Example": "-----BEGIN PGP PRIVATE KEY-----",
        "Secret": "-----BEGIN PGP PRIVATE KEY-----",
        "Comment": "Should capture private key headers",
    },
    {
        "RuleID": "asymmetric-private-key",
        "Example": "-----BEGIN OPENSSH PRIVATE KEY-----\\n0b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd029920b3d576ba5a108c3b7374142bfd02992\\n-----END OPENSSH PRIVATE KEY-----",
        "Secret":   "-----BEGIN OPENSSH PRIVATE KEY-----",
        "Comment": "Should capture private key headers",
    },
]

SHOULD_NOT_MATCH = [
    # Very WIP just here to unblock testing
    # {
    #     "Example": "-----BEGIN PGP PRIVATE KEY-----",
    #     "File": "test/testec-p112r1.pem",
    #     "Comment": "Common test files in the open ssl project and others",
    # },
    # {
    #     "Example": "-----BEGIN EC PRIVATE KEY-----\\nkey\\n-----END EC PRIVATE KEY-----",
    #     "Comment": "Shouldn't match such a short key",
    # },
    # {
    #     "Example": "-----BEGIN RSA PRIVATE KEY-----\\nREPLACE_ME\\n-----END RSA PRIVATE KEY-----",
    #     "Comment": "Shouldn't match such a short key",
    # },
    # {
    #     "Example": "-----BEGIN PRIVATE KEY-----\\nMII.....RSA KEY WITHOUT LINEBREAKS\\n-----END PRIVATE KEY-----",
    #     "Comment": "Shouldn't match an inline key with spaces in it",
    # },
]


class TestGitLeaks(TestCase):
    test_dir = Path(__file__).resolve().parent
    patterns_path = Path("/tmp/leaktk-patterns-{VERSION}-patterns.toml")
    maxDiff = 10000

    def setUp(self):
        build_patterns = self.test_dir.joinpath(
            "..", "..", "..", "target", "patterns", "gitleaks", VERSION,
        )
        shutil.copy(build_patterns, self.patterns_path)

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
                    entry["Example"]
                    for entry in SHOULD_NOT_MATCH + SHOULD_MATCH
                    if not "File" in entry
                )
            )

        # Handle ones with custom filenames
        for entry in SHOULD_NOT_MATCH + SHOULD_MATCH:
            if "File" not in entry:
                continue

            custom_file_path = self.test_pattern_dir.joinpath(entry["File"])

            if not custom_file_path.parent.is_dir():
                custom_file_path.parent.mkdir(parents=True)

            with open(custom_file_path, "a+") as custom_file:
                custom_file.write(entry["Example"] + "\n")

    def test_patterns(self):
        """
        Run gitleaks against the general test contents using the latest patterns
        """
        cmd = [
            f"gitleaks-{VERSION}",
            "detect",
            "--no-git",
            "--report-format=json",
            "--report-path=/dev/stdout",
            f"--config={self.patterns_path}",
            f"--source={self.test_pattern_dir}",
        ]

        completed_process = subprocess.run(cmd, capture_output=True, check=False)
        leaks = json.loads(completed_process.stdout)

        # These are the Secrets found above. This will need to be updated
        # when adding a new item to test.
        matches = {(m["RuleID"], m["Secret"]) for m in SHOULD_MATCH}

        for leak in leaks:
            leak_key = (leak["RuleID"], leak["Secret"])

            self.assertIn(leak_key, matches)
            matches.remove(leak_key)

        # Make sure everything's been accounted for
        self.assertEqual(matches, set())
