# Patterns

Patterns leveraged by LeakTK

## Status

- gitleaks
  - `7.6.1` actively maintained
  - `>=8.18.2,<9.0.0` actively maintained
- considering patterns to include for other types of scans

## Structure

### patterns folder

The patterns folder is structured `patterns/{tool}/{version}/{patterns_files}`.

Pattern files are broken into separate files and merged together by `make all`
command. The reason for this is to it make it easier to merge these patterns
with existing internal patterns.

### tests folder

There is also a tests folder that follows a structure similar to patterns.
Use `make test` to run the tests.

### testdata folder

Contains all the data the tests are ran against as well as expected results

### scripts folder

The `scripts` folder is for various scripts used to maintain the project.

### target folder

The result of running `make all` and follows a similar format to the patterns
folder with the exception that all of the patterns for a specific version have
been merged into a single file with the format:
`target/patterns/{tool}/{version}`.

## Tags

All tags should be lower case and multi-word tags should be
`separated-by-dashes`.

There are special tags that the tooling consumes that should
be formatted `<type>:<name>`.

These are the special tags:

* `alert:{repo-owner,analyst}` - who should be alerted if a leak is found
* `group:<group-name>` - who should have access to the rule
* `type:<pattern-type>` - the type of thing the pattern targets

In the context of this repo `group` mainly serves as a way to mark tags for
testing. Open sourcing the pattern-server is on the road map and
it will be the main consumer of these group tags.

Patterns tagged `group:leaktk-testing` are not ready for production use and
should be placed in the 99-testing.toml. Please read the comments at the top of
that file for further instructions regarding testing patterns.

These are the supported, predefined `type` tags:

* `type:secret` - data that should never be in a repo
* `type:cui` - controlled unclassified information
* `type:infra` - infrastructure, host names, etc
* `type:ioc` - an indicator of compromise
* `type:pii` - personally identifiable information
* `type:vuln` - a CVE, vulnerable dep, or known flaw

Custom `type` tags should be namespaced to avoid collisions with future tags.
For example if you were writing tags for a company called WidgetCorp and you
wanted to search for internal only information, you could create a
`type:widgetcorp-internal` tag.

## Ignoring false positives

The standard LeakTK ignore tag is `notsecret`. Since the LeakTK scanner may
leverage multiple scanners, their ignore tags may also work in certain cases,
but `notsecret` will be supported across all of them.

For the scanner to pick it up it must:

* Start with comment characters, a space, or be at the beginning of the line
* End with a space or be at the end of the line

Search the patterns for `notsecret` to see the exact regex pattern.

## Make targets

### all

Builds all of the patterns under a `target` folder.

### clean

Clears out built files.

### test

Runs tests to validate the patterns. This requires python3 and it pulls (and
checksums) its own version of the scanner tools to use in the tests.

# TODO

1. Put together a deprecation plan for the old patterns
1. Provide patterns for [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
1. Start a project for managing secret scanning patterns in a GitHub repo via its [REST API](https://docs.github.com/en/rest/secret-scanning)
1. Consider [CodeQL](https://codeql.github.com/) support
