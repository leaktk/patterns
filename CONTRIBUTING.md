# Contributing to Patterns

Thank you for considering contributing to this project! Your help is greatly
appreciated. This document provides guidelines for contributing to the patterns
repository.

## Repository Structure Overview

- **`patterns/`**: Contains the pattern files, organized by tool and version
  (e.g., `patterns/gitleaks/8.18.2/`).

- **`scripts/`**: Includes various helper scripts for tasks like compiling
  patterns, checking for duplicate IDs, and testing.

- **`target/`**: This directory contains the compiled patterns after running
  `make build` or `make test`. Changes in this directory that are a result of
  your pattern modifications should be committed.

- **`testdata/`**: Holds data used for testing, including the `fake-leaks`
  submodule and expected results files.

- **`tests/`**: Contains the test scripts for validating patterns.

- **`Makefile`**: Defines build, clean, format, and test targets.

- **`README.md`**: Provides an overview of the project, status, structure,
  tagging guidelines, and how to ignore false positives.


## How to Contribute

We welcome contributions in various forms, including new patterns, improvements
to existing patterns, documentation enhancements, and bug fixes.

### Steps

1. If not a member, [fork the repository][fork]

2. Review the [style guide](#style-guide)

3. [Add/update rules](#rule-format)

4. [Compile and test](#compile-and-test)

5. Commit changes—including the compiled rules

6. Submit a [pull request][pull-request]

### Style Guide

#### Gitleaks 7

- Follow the rules for [Gitleaks 8](#gitleaks-8) except:
  - Do not include fields that are unused by Gitleaks 7 (e.g. `id` & `keywords`).
  - Make sure the rules are in the [Gitleaks 7 format][gl7conf].
  - Use `paths` instead of the `files` field in allowlists.

#### Gitleaks 8

- Use 2 spaces for indentation.
  - 2 was selected to keep things consistent in the files.
- Indent the body of [TOML tables][tt] and sub-tables like allowlists should be indented as if they were in the body of their parent.
  - Done to help visually see what's in a table and that the allowlist is part of the rule.
- IDs must be 8 unique, random b64url encoded bytes with the padding trimmed.
  - Use [genid](./scripts/genid) to generate IDs.
- The description field must be written in title case.
  - Good: `AWS Access Key ID`
  - Bad: `AWS access key id`
- The description field must describe the finding and not the rule.
  - Good: `Foo Inc. Domain`
  - Bad: `Domains for Foo Inc that could expose their infrastructure details`
- The description field must be singular.
  - Good: `GitHub Fine-Grained PAT`
  - Bad: `GitHub Fine-Grained PATs`
- The description field must have the subject/platform/company-name at the beginning.
  - Good: `Openshift Token`
  - Bad: `Tokens for OpenShift`
- Use keywords when appropriate to improve rule performance.
  - Literal strings from the rule usually make good keywords
- Write keywords all lower case
  - Keywords are case insensitive so we write them lower case to help communicate that.
- Use triple single quotes for all regex (e.g. `'''something.*here'''`).
  - This helps with writing escapes so that you don't have to escape the escapes
- Use single quotes for other strings.
  - This is mainly to keep things consistent for tooling working with the source files.
  - It may also parse _slightly_ faster.
- Escape quotes (both single and double) in regexes.
  - This helps when copy/pasting regexes into other systems.
  - Also writing the regex to be as portable as possible is helpful.
- Include proper `type:` tags (see [README][rm] for info on type tags)
  - This is usually `type:secret`
- New rules must include a `group:leaktk-testing` tag and no `alert:` tag
  - We let new rules "bake" for a while before promoting them to production
- Follow any additional instructions at the top of the pattern files
  - Files like the `-testing` files may contain extra instructions
- If writing a fairly complicated rule, include new test cases.
  - The [fake-leaks repo][fl] contains the test data for this repo.
  - Other patterns repos may include the test data directly with the repo.

### Rule Format

Patterns are separated by provider (e.g. `gitleaks`, `leaktk`). Chances are you
are going to want to write a Gitleaks rule. Under the provider, there are
folders for the versions of the rule format supported. If you only want to
write a rule for the latest version of LeakTK, you can target the latest
version of the Gitleaks patterns. Gitleaks 7.6.1 patterns are rarely updated
anymore and are only kept around for now to support an internal tool that
we are deprecating.

Links to format docs for the rules:

- [gitleaks-7.6.1][gl7conf]
- [gitleaks-v8.27.0][gl8conf]

Only write rules and allowlists. Other items like `[extend]` are not supported.

### Compile And Test

Since this repo also acts as a basic pattern server, it's important to compile
and test your rules before submitting a PR. The compiled rules are what the
scanner actually fetches.

To compile and test the changes, run:

```
make clean format test
```

The files created by compiling the rules should be included in the pull request.

[pull-request]: https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request
[fork]: https://docs.github.com/en/pull-requests/reference/forks
[gl7conf]: https://github.com/gitleaks/gitleaks/tree/v7.6.1#configuration
[gl8conf]: https://github.com/gitleaks/gitleaks/tree/v8.27.0#configuration
[fl]: https://github.com/leaktk/fake-leaks
[rm]: ./README.md
[tt]: https://toml.io/en/v1.0.0#table
