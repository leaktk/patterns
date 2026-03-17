package leaktk.analyst

response := input
findings := response.results
analyzed_finding_ids := {f.id | some f in analyzed_findings}
unanalyzed_findings := {
object.union(finding, {"valid": null, "analysis": null}) |
  some finding in findings
  not analyzed_finding_ids[finding.id]
}

analyzed_response := object.union(response, {"results": analyzed_findings | unanalyzed_findings})


# Utils
auth_bearer_token_valid(opts) if {
  http.send({
    "url": opts.url,
    "method": "GET",
    "headers": {"Authorization": sprintf("Bearer %s", [opts.token])},
  }).status_code < 300
}

# GitHub Tokens
analyzed_findings contains analyzed_finding if {
  some finding in findings
  contains(lower(finding.rule.description), "github")
  regex.match("^(?:gh[porsu]_|github_pat_)", finding.secret)
  analyzed_finding := object.union(finding, {"valid": auth_bearer_token_valid({
    "url": "https://api.github.com/rate_limit",
    "token": finding.secret,
  })})
}

# Hugging Face Tokens
analyzed_findings contains analyzed_finding if {
  some finding in findings
  contains(lower(finding.rule.description), "hugging")
  regex.match("^hf_[a-zA-Z]{34}$", finding.secret)
  analyzed_finding := object.union(finding, {"valid": auth_bearer_token_valid({
    "url": "https://huggingface.co/api/whoami-v2",
    "token": finding.secret,
  })})
}

# PyPI Tokens
analyzed_findings contains analyzed_finding if {
  some finding in findings
  contains(lower(finding.rule.description), "pypi")
  regex.match("^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,1000}$", finding.secret)
  resp := http.send({
    "url": "https://upload.pypi.org/legacy/",
    "method": "POST",
    "raw_body": ":action=file_upload",
    "headers": {
      "Authorization": sprintf("Basic %s", [base64.encode(concat(":", ["__token__", finding.secret]))]),
      "Content-Type": "application/x-www-form-urlencoded",
    },
  })
  valid := resp.status_code == 400 # Valid token but invalid operation
  analyzed_finding := object.union(finding, {"valid": valid})
}

# Slack User Tokens
analyzed_findings contains analyzed_finding if {
  some finding in findings
  contains(lower(finding.rule.description), "slack")
  regex.match("^xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}$", finding.secret)
  resp := http.send({
    "url": "https://slack.com/api/auth.test",
    "method": "POST",
    "headers": {"Authorization": sprintf("Bearer %s", [finding.secret])},
  })
  analyzed_finding := object.union(finding, {
    "valid": resp.body.ok,
    "analysis": resp.body,
  })
}
