import re

from unittest import TestCase

from .helpers import GITLEAKS_PATTERNS_PATH

tag_re = re.compile(r"\s*tags\s*=\s*(\[.*\])\s*")


class TestGitLeaks(TestCase):
    def patterns_paths(self):
        for dirpath, _, filenames in GITLEAKS_PATTERNS_PATH.walk():
            for filename in filenames:
                yield dirpath / filename

    def tag_lines(self):
        for path in self.patterns_paths():
            with open(path, "r", encoding="UTF-8") as patterns_file:
                for line in patterns_file:
                    match = tag_re.match(line)

                    if match:
                        yield line.strip()

    def test_valid_tags(self):
        tags_valid = re.compile(
            r"\s*tags\s*=\s*\[(?:\s*[\"[a-z]*:?[a-z0-9\-]+\",?\s*)+\]"
        )
        type_re = re.compile(r"\"type:([a-z0-9\-]+)\"")
        valid_types = {"secret", "infra", "ioc", "pii", "vuln"}

        for tag_line in self.tag_lines():
            # Check the tag format
            self.assertTrue(
                bool(tags_valid.match(tag_line)),
                f"improperly formatted tag: {tag_line}",
            )

            # Check the type values
            type_tags = set(type_re.findall(tag_line))
            self.assertEqual(
                type_tags - valid_types,
                set(),
                f"invalid type tag: {tag_line}",
            )
