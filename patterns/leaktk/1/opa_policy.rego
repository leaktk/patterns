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

# Helper rule to validate a Google Cloud Platform (GCP) API key
validate_gcp_api_key(api_key) := is_valid if {
	res := http.send({
		"method": "POST",
		"url": sprintf("https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=%s", [api_key]),
		"headers": {
			"Content-Type": "application/json",
			"User-Agent": "LeakTK-Validator",
		},
		"body": json.marshal({
			"continueUri": "http://localhost",
			"identifier": "test@example.com",
		}),
		"raise_error": false,
	})

	# An invalid/revoked key returns HTTP 400 with "API_KEY_INVALID" or HTTP 403
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
