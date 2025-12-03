package analyst
response := input
findings := response.results
analyzed_finding_ids := {f.id | some f in analyzed_findings}
unanalyzed_findings := {
  object.union(finding, {"valid": null, "analysis": null})
  | some finding in findings; not analyzed_finding_ids[finding.id]
}
# GitHub Tokens
analyzed_findings contains analyzed_finding if {
  some finding in findings
  contains(lower(finding.rule.description), "github")
  regex.match("^(?:gh[porsu]_|github_pat_)", finding.secret)
  analyzed_finding := object.union(finding, {
    "valid": http.send({
      "url": "https://api.github.com/rate_limit",
      "method": "GET",
          "headers": {"Authorization": sprintf("Bearer %s", [finding.secret])},
    }).status_code < 300,
    "analysis": {"todo": "some real analysis here"},
  })
}
analyzed_response := object.union(response, {
  "results": analyzed_findings | unanalyzed_findings,
})
