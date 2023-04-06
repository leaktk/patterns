import os
import subprocess


def copy_if(a, a_key, b, b_key):
    """
    Copy a_key to b_key if a_key exists in a
    """
    if a_key in a:
        b[b_key] = a[a_key]


def write_examples(tests, test_dir):
    """
    Used for writing the examples out to a test dir
    """
    for test in tests:
        path = os.path.join(test_dir, test.get("path", "examples"))
        parent_dir = os.path.dirname(path)

        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        with open(path, "a", encoding="UTF-8") as test_file:
            test_file.write(test["example"] + "\n")


def gitleaks(version, *args, **kwargs):
    """
    A wrapper for running supported versions of gitleaks
    """
    return subprocess.run(
        [f"./scripts/gitleaks-{version}", *args],
        capture_output=True,
        check=False,
        shell=False,
        timeout=60,
        **kwargs,
    )
