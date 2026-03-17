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
default auth_bearer_token_valid(opts) := false

auth_bearer_token_valid(opts) if {
	http.send({
		"url": opts.url,
		"method": "GET",
		"headers": {"Authorization": sprintf("Bearer %s", [opts.token])},
	}).status_code < 300
}

container_registry_auth_opts(hostname) := opts if {
	lower(hostname) == "docker.io"
	opts := {
		"url": "https://auth.docker.io/token",
		"params": {},
	}
} else := opts if {
	contains(lower(hostname), "quay")
	opts := {
		"url": sprintf("https://%s/v2/auth", [hostname]),
		"params": {},
	}
} else := opts if {
	contains(lower(hostname), "redhat")
	opts := {
		"url": "https://sso.redhat.com/auth/realms/rhcc/protocol/redhat-docker-v2/auth",
		"params": {
			"service": "docker-registry",
			"client_id": "validate-token",
			"scope": "repository:rhel:pull",
		},
	}
} else := opts if {
	opts := {
		"url": sprintf("https://%s/v2", [hostname]),
		"params": {},
	}
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

# Slack API Tokens
analyzed_findings contains analyzed_finding if {
	some finding in findings
	contains(lower(finding.rule.description), "slack")
	regex.match(`^xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}|xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}$`, finding.secret)
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

# Slack Webhook URLs
analyzed_findings contains analyzed_finding if {
	some finding in findings
	contains(lower(finding.rule.description), "slack")
	regex.match("^(?:https?:\/\/)?hooks.slack.com\/(?:services|workflows|triggers)", finding.secret)
	resp := http.send({
		"url": finding.secret,
		"method": "POST",
		"raw_body": "junk-data",
		"headers": {"Content-Type": "application/json"},
	})
	analyzed_finding := object.union(finding, {"valid": resp.status_code == 400})
}

# Container Registry Auths
analyzed_findings contains analyzed_finding if {
	some finding in findings
	contains(lower(finding.rule.description), "container")
	contains(lower(finding.rule.description), "auth")
	matches := regex.find_all_string_submatch_n(
		`\"((?:[0-9a-zA-Z\-]{1,66}\.)+[0-9a-zA-Z]+)\\*\"\s*:\s*\{[\s\S]{0,256}?\"auth\\*\"\s*:\s*\\*\"([^\"]+?)\\*\"`,
		finding.secret,
		-1,
	)

	valid_auths := {hostname: {"user": split(base64.decode(auth), ":")[0]} |
		some match in matches
		hostname := match[1]
		auth := match[2]
		opts := container_registry_auth_opts(hostname)
		resp := http.send({
			"url": concat("?", [opts.url, urlquery.encode_object(opts.params)]),
			"method": "GET",
			"headers": {"Authorization": sprintf("Basic %s", [auth])},
		})
		resp.status_code == 200
	}

	analyzed_finding := object.union(finding, {
		"valid": count(valid_auths) > 0,
		"analysis": {"valid_auths": valid_auths},
	})
}

# MailChimp API Tokens
analyzed_findings contains analyzed_finding if {
	some finding in findings
	contains(lower(finding.rule.description), "mailchimp")
	regex.match(`^[0-9a-f]{32}-us[0-9]{1,2}$`, finding.secret)
	dc := split(finding.secret, "-")[1]
	analyzed_finding := object.union(finding, {"valid": auth_bearer_token_valid({
		"url": sprintf("https://%s.api.mailchimp.com/3.0/ping", [dc]),
		"token": finding.secret,
	})})
}

# Stripe API Tokens
analyzed_findings contains analyzed_finding if {
	some finding in findings
	contains(lower(finding.rule.description), "stripe")
	regex.match(`(?i)^[sr]k_live_[0-9a-zA-Z]{24}$`, finding.secret)
	analyzed_finding := object.union(finding, {"valid": auth_bearer_token_valid({
		"url": "https://api.stripe.com/v1/account",
		"token": finding.secret,
	})})
}

# SendGrid API Keys
analyzed_findings contains analyzed_finding if {
	some finding in findings
	contains(lower(finding.rule.description), "sendgrid")
	regex.match(`^SG\.[\w\-]{16,32}\.[\w\-]{16,64}$`, finding.secret)
	analyzed_finding := object.union(finding, {"valid": auth_bearer_token_valid({
		"url": "https://api.sendgrid.com/v3/scopes",
		"token": finding.secret,
	})})
}
