# Patterns

Leak patterns for LeakTK tools to use

## Status

Currently cleaning and open sourcing patterns from an
internal tool. There are plans to migrate these patterns to the
latest version of gitleaks.

## Structure

### patterns folder

The patterns folder is structured `patterns/{tool}/{version}/{patterns_files}`.

Currently the only supported tool is
[gitleaks](https://github.com/zricethezav/gitleaks),
and for the moment the only supported version is 7.6.1. If multiple versions
support the same patterns format, the version folder may be a symlink.
8.12.0 support is planned.

Pattern files are broken into separate files and merged together by `make all`
command. The reason for this is to it make it easier to merge these patterns
with existing internal patterns.

### tests folder

There is also a tests folder that follows a structure similar to patterns.
Use `make test` to run the tests.

### scripts folder

The `scripts` folder is for various scripts used to maintain the project.

### target folder

The result of running `make all` and follows a similar format to the patterns
folder with the exception that all of the patterns for a specific version have
been merged into a single file (e.g. `target/patterns/gitleaks/7.6.1`).

## Tags

All tags on these patterns should be lower case and multi-word tags should be
`separated-by-dashes`.

Also there are special metadata tags that the tooling will consume that should
be formatted `tag-type:tag-name`.

Here's an overview of the "special" tags that the tooling will leverage:

* `alert:{repo-owner,analyst}` - who should be alerted if a leak is found
* `group:<group-name>` - who should have access to the rule
* `type:<pattern-type>` - the type of thing the pattern targets

In the context of this repo `group` mainly serves as a way to mark tags for
testing. Open sourcing the pattern-server is on the road map and
it will be the main consumer of these group tags.

Patterns with the tag `group:leaktk-testing` means they are not ready for
production use (i.e. they may be very spammy).

In the future there may be additional tag types added, so assume that tags
containing a colon are meant to provide metadata to other LeakTK tools about
how to handle certain leaks.

`type` tags indicate what the pattern is searching for. Here are some
predefined tags:

* `type:secret` - secrets that should never be exposed somewhere the scanner should be able to reach
* `type:vulnerability` - a CVE, vulnerable dep, or known flaw
* `type:pii` - personally identifiable information
* `type:infrastructure` - information about infrastructure, host names, etc

If defining custom tags, namespace them to avoid collisions with future tags.
For example if you were writing tags for a company called WidgetCorp and you
wanted to search for internal only information, you could create a
`type:widgetcorp-internal` tag.

## Make targets

### all

Builds all of the patterns under a `target` folder.

### clean

Clears out built files.

### test

Runs tests to validate the patterns. This requires python3 and it pulls (and
checksums) its own version of the scanner tools to use in the tests.
