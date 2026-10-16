# OWASP Top 10 policy pack (plan §9).
#
# Blocks on newly introduced findings that map to an OWASP Top 10 category via
# CWE. Layer it on top of baseline: policy_packs: [baseline, owasp-top10].
package gatehouse.gates

import rego.v1

# CWEs that place a finding in a (high-signal) OWASP category we gate on.
owasp_blocking_cwes := {
	"CWE-89", "CWE-78", "CWE-77", "CWE-94", # A03 Injection
	"CWE-79",                               # A03 XSS
	"CWE-22",                               # A01 Path traversal
	"CWE-918",                              # A10 SSRF
	"CWE-502",                              # A08 Insecure deserialisation
	"CWE-798",                              # A02/A07 Hard-coded creds
}

deny contains msg if {
	some f in input.findings
	f.status == "new"
	not f.waived
	some cwe in f.cwe_ids
	owasp_blocking_cwes[cwe]
	msg := sprintf("[owasp] New %s finding %s (%s) in %s:%d", [f.severity, f.rule_id, cwe, f.path, f.line])
}
