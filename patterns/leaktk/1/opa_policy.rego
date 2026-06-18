package leaktk.analyst

import future.keywords.if
import future.keywords.in

response := input
findings := response.results

analyzed_response := {
	"results": ai_processed_findings
}

ai_processed_findings := [ ai_finding |
	some finding in findings
	prediction := leaktk.ai.RunModel("LogisticRegression", finding)
	
	ai_finding := object.union(finding, {
		"valid": prediction.probability > 0.8,
		"analysis": {
			"ai_model": "Logistic Regression",
			"probability": prediction.probability,
		},
	})

]
