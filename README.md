# Patterns

Leak patterns for LeakTK tools to use

## Status

Work in progress. Currently cleaning and open sourcing patterns from an
internal tool.

## Structure

The patterns folder is structured `patterns/{tool}/{version}/{patterns_files}`

Currently the only supported tool is
[gitleaks](https://github.com/zricethezav/gitleaks).
And the only supported version is 7.6.1, but there are plans to translate these
patterns to the latest version.

There is also a `tests` folder that follows a similar structure. Use `make test`
to run the tests.

The `scripts` folder is for various scripts used to maintain the project.

More info to come as the patterns are moved over. It's likely that the patterns
files will be broken into separate files and merged together by build command.
The reason for this is so that it makes it easier to merge these patterns with
existing internal only patterns in the future, but we'll see!

## Tags

All tags on these patterns should be lower case and multi-word tags should be
`separated-by-dashes`.

Also there are special meta data tags that the tooling will consume that should
be formatted `type:tag-name`.

Here's an overview of the "special" tags that the tooling will leverage:

* `alert:{repo-owner,analyst}` - determines who should be alerted if a leak is found
* `group:<group-name>` - determines who should have access to the tag

In the context of this repo `group` mainly serves as a way to mark tags for
testing. Open sourcing the pattern-distribution-server is on the road map and
it will be the main consumer of these group tags.

Patterns with the tag `group:leaktk-testing` means they are not ready for
production use (i.e. they may be very spammy).

In the future there may be additional tag types added, so assume that tags
containing a colon are meant to provide metadata to other LeakTK tools about
how to handle certain leaks.
