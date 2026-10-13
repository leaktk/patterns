package leaktk.analyst

import future.keywords.if
import future.keywords.in

response := input
findings := response.results

# Helper rule to validate a GitHub token directly against the GitHub API
validate_github_token(token) := is_valid if {
	res := http.send({
		"method": "GET",
		"url": "https://api.github.com/user",
		"headers": {
			"Authorization": sprintf("Bearer %s", [token]),
			"User-Agent": "LeakTK-Validator",
		},
    "raise_error": false,
	})
	is_valid := res.status_code == 200
}

analyzed_response := {
	"results": ai_processed_findings
}

ai_processed_findings := [ ai_finding |
	some finding in findings
	prediction := leaktk.ai.RunModel("LogisticRegression", finding)

  github_token_valid := validate_github_token(finding.secret)
	
	ai_finding := object.union(finding, {
		"valid": prediction.probability > 0.8,
		"analysis": {
			"ai_model": "Logistic Regression",
			"probability": prediction.probability,
      "github_api_valid": github_token_valid,
		},
	})

]
