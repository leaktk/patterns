# Patterns

Patterns leveraged by LeakTK

## Pattern Support

| Provider      | Version   | State          |
| ------------- | --------- | -------------- |
| Gitleaks      | 8.27.0    | **Maintained** |
| Betterleaks   | 2.0.0     | Planned        |
| LeakTK        | 1         | Not Released   |
| Gitleaks      | 7.6.1     | _Deprecated_   |
| Gitleaks      | 8.18.2    | _Deprecated_   |

Pattern sets can be found at: `target/patterns/{provider}/{version}`

## Tags

### Tag Format

All tag values are `lower-kabob-case`. There are special, prefixed tags that
our tooling consumes or produces. They are formatted: `<prefix>:<value>`.

### Special Tags

Tags with these prefixes have special meaning to LeakTK (except for `ext:`).
We may add more special tags in the future. If you want to define your own
prefix, prepend `ext:` to avoid collisions with future prefixes.

| Tag                    | Meaning                                            |
| ---------------------- | -------------------------------------------------- |
| `alert:<audience>`     | Identifies who should be alerted for a finding     |
| `group:<group-name>`   | Group rules for access control and release phases  |
| `type:<finding-type>`  | Categorize findings                                |
| `vis:<src-visibility>` | Indicate the visibility of the source if known     |
| `sev:<level>`          | Indicate the severity of the finding               |
| `ext:<prefix>:<value>` | User defined prefixes ignored by LeakTK            |

#### Alert Tags

> **Note**: These will be removed from the rules in the future. They will
> remain valid tags, but will added to a finding by a tool's policy instead of
> being defined on the rule itself.

Alert tags provide two bits of information:

- Is this worth telling anyone about?
- Who should be told?

Currently supported values:

| Tags               | Description                                            |
| ------------------ | ------------------------------------------------------ |
| `alert:repo-owner` | Person who is likely able to address the finding[^1]   |
| `alert:analyst`    | Incident response analyst if supported by the tool     |


#### Group Tags

Groups serves as a way to mark tags for testing and for restricting rule access
by scenario or access control.

We have an internal pattern server implementation that provides scoped access
to rules and open sourcing it is on the road-map.

Patterns tagged `group:leaktk-testing` are in their test phase and are not
ready for production.

#### Type Tags

These are the supported, predefined `type` tags:

| Tag           | Finding Indicates                                           |
| ------------- | ----------------------------------------------------------- |
| `type:secret` | [Secret / Sensitive Information][secret_def]                |
| `type:infra`  | [Infrastructure Details][infra_def]                         |
| `type:crd`    | [Credential][cred_def]                                      |
| `type:cid`    | Credential Identifier[^2]                                   |
| `type:cui`    | [Controlled Unclassified Information][cui_def]              |
| `type:flg`    | [LeakTK Test Flags][#flags]                                 |
| `type:ioc`    | [Indicator of Compromise][ioc_def]                          |
| `type:phi`    | [Protected Health Information][phi_def]                     |
| `type:pii`    | [Personally Identifiable Information][pii_def]              |
| `type:vln`    | [Vulnerability][vuln_def]                                   |

Custom `type` tags should be namespaced to avoid collisions with future tags.
For example if you were writing tags for a company called WidgetCorp and you
wanted to search for internal only information, you could create a
`type:widgetcorp-internal` tag.

#### Visibility Tags

These tags can be set by the tooling to indicate the finding's visibility rather
than adding them directly to a rule.

Current values:

| Tag        | Description                                                    |
| ---------- | -------------------------------------------------------------- |
| `vis:unk`  | Visibility is unknown (same as omitting the tag)               |
| `vis:pub`  | Visible to the public internet                                 |
| `vis:int`  | Visible to special networks or platform wide                   |
| `vis:prv`  | Requires authentication and specific privileges to access it   |


#### Severity Tags

These tags can be set by the tooling to indicate the finding's severity. They
may also be set on a rule to indicate the default assumed severity.

Current values:

| Tag        | Name     | Description                                         |
| ---------- | -------- | --------------------------------------------------- |
| `sev:inf`  | Info     | Context & information that poses no risk            |
| `sev:low`  | Low      | See note below                                      |
| `sev:med`  | Medium   | See note below                                      |
| `sev:hgh`  | High     | See note below                                      |
| `sev:crt`  | Critical | See note below                                      |

These tags are highly contextual and defaults are a bit subjective. We've done
some internal work to better classify these. The goal is to work with a few
others in the secret scanning community to put together mostly objective
definitions for these and reference those from this doc.

## Flags

These patterns include a special rule for [CTF-style][ctf_def] flags formatted:

```
LTKF{value}
```

Where value can be any `[a-z]{2,16}` except `public` which is ignored to act as
a false positive flag.

The values generally should correspond to the types above e.g.:

```
LTKF{secret}
LTKF{cui}
LTKF{infra}
...
```

## Make Targets

| Target     | Description                                                    |
| ---------- | ---------------------------------------------------------------|
| `build`    | Compile patterns into the provided formats                     |
| `clean`    | Deletes compiled patterns and removes git ignored files        |
| `format`   | Format tests, test results, and pattern sources                |
| `test`     | Run pattern tests and checks                                   |

[cred_def]: https://github.com/secret-scanning-sig/glossary/blob/main/C/Credential.md
[ctf_def]: https://en.wikipedia.org/wiki/Capture_the_flag_(cybersecurity)
[cui_def]: https://en.wikipedia.org/wiki/Controlled_Unclassified_Information
[vuln_def]: https://en.wikipedia.org/wiki/Vulnerability_(computer_security)
[infra_def]: https://attack.mitre.org/tactics/TA0043/
[ioc_def]: https://en.wikipedia.org/wiki/Indicator_of_compromise
[pii_def]: https://en.wikipedia.org/wiki/Personal_data
[secret_def]: https://github.com/secret-scanning-sig/glossary/blob/main/S/Secret.md

[^1]: This will probably change in the future to something like `author` or
      similar.

[^2]: A credential identifier can be something like an AWS IAM Unique ID,
      username, or similar that is combined with with the rest of the
      credential to provide or gain access. These have their own category
      because it may be low risk to store them in certain places internally
      that would be higher risk if public.
