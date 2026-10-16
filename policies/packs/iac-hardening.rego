# iac-hardening policy pack (plan §9): gate on infrastructure-as-code and
# container-configuration findings. Layer on baseline.
package gatehouse.gates

import rego.v1

# New high/critical IaC or container misconfigurations block.
deny contains msg if {
	some f in input.findings
	f.type in {"iac", "container"}
	f.status == "new"
	f.severity_n >= 4 # high or critical
	not f.waived
	msg := sprintf("[iac] New %s %s finding %s in %s", [f.severity, f.type, f.rule_id, f.path])
}

# New medium IaC/container findings warn.
warn contains msg if {
	some f in input.findings
	f.type in {"iac", "container"}
	f.status == "new"
	f.severity_n == 3 # medium
	not f.waived
	msg := sprintf("[iac] New medium %s finding %s in %s", [f.type, f.rule_id, f.path])
}
