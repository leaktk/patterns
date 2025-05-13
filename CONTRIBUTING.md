# Contributing to Patterns

Thank you for considering contributing to this project\! Your help is greatly
appreciated. This document provides guidelines for contributing to the patterns
repository.

## How to Contribute

We welcome contributions in various forms, including new patterns, improvements
to existing patterns, documentation enhancements, and bug fixes.

### Getting Started

1. **Fork the Repository:** Start by forking the repository to your own GitHub
   account.

2. **Clone Your Fork:** Clone your forked repository to your local machine:
   ``` bash
   git clone https://github.com/YOUR_USERNAME/patterns.git
   cd patterns
   ```

3. **Set Upstream Remote:** Add the original repository as an upstream remote:
   ``` bash
   git remote add upstream https://github.com/leaktk/patterns.git
   ```

4. **Create a Branch:** Create a new branch for your changes:
   ``` bash
   git checkout -b your-feature-branch
   ```

### Making Changes

When making changes, please keep the following guidelines in mind:

- **Run Tests:** Before submitting your changes, ensure all tests pass by
  running:
  ``` bash
  make test
  ```
  This command will also automatically update files in the `target/*` directory.
  These changes should be included in your pull request.

- **Format Code:** Ensure your changes are formatted correctly by running:
  ``` bash
  make format
  ```

- **New Rules and Examples:**
  - All new rules must have corresponding examples in the
    [fake-leaks repository](https://github.com/leaktk/fake-leaks). This
    repository is included as a submodule and can be updated using
    `git submodule update --init --recursive`.
  - Ensure new regex patterns have clear comments explaining what they are
    looking for or why they are there.

- **Coding Style:**
  - Use single quotes for strings.
  - Use triple single quotes for regexes (e.g., `'''regex_pattern'''`).
  - Follow the existing indentation patterns in the files.

- **Tagging Guidelines:** Adhere to the tagging guidelines outlined in the
  [README.md](./README.md).
  This includes using lowercase for tags, separating multi-word tags with
  dashes, and using special tags like `alert:<target>`, `group:<group-name>`,
  and `type:<pattern-type>`.

### Submitting Pull Requests

1.  **Commit Your Changes:** Make clear and concise commit messages.

2.  **Push to Your Fork:**
    ``` bash
    git push origin your-feature-branch
    ```

3.  **Open a Pull Request:** Go to the original repository on GitHub and open a
    pull request from your forked branch. Provide a clear description of the
    changes you've made.

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

We look forward to your contributions!
