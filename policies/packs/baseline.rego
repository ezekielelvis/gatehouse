# Gatehouse baseline policy pack.
#
# The shipped default gate: block newly introduced secrets, new high/critical
# vulnerable dependencies, and failing (non-quarantined) tests; warn on low
# changed-lines coverage. It deliberately blocks only on *new* issues so the
# gate is usable on legacy code from day one (plan §9).
#
# Policies contribute to two string sets, `deny` and `warn`, in package
# gatehouse.gates. Any deny fails the run; otherwise any warn warns.
package gatehouse.gates

import rego.v1

# --- Secrets -----------------------------------------------------------------

# A newly introduced secret blocks any run.
deny contains msg if {
	some f in input.findings
	f.type == "secret"
	f.status == "new"
	not f.waived
	msg := sprintf("New secret detected: %s in %s:%d", [f.rule_id, f.path, f.line])
}

# In pre-commit, ANY secret blocks (there is no base to diff against yet).
deny contains msg if {
	input.context == "pre-commit"
	some f in input.findings
	f.type == "secret"
	not f.waived
	msg := sprintf("Secret present: %s in %s", [f.rule_id, f.path])
}

# --- Dependency vulnerabilities (SCA) ----------------------------------------

# New high or critical vulnerable dependencies block.
deny contains msg if {
	some f in input.findings
	f.type == "vulnerability"
	f.status == "new"
	f.severity_n >= 4 # high(4) or critical(5)
	not f.waived
	msg := sprintf("New %s vulnerability %s in %s", [f.severity, f.rule_id, f.path])
}

# --- SAST --------------------------------------------------------------------

# New critical SAST findings block.
deny contains msg if {
	some f in input.findings
	f.type == "sast"
	f.status == "new"
	f.severity_n >= 5 # critical
	not f.waived
	msg := sprintf("New critical SAST finding %s in %s:%d", [f.rule_id, f.path, f.line])
}

# New high SAST findings warn (promote to deny in strict-release).
warn contains msg if {
	some f in input.findings
	f.type == "sast"
	f.status == "new"
	f.severity_n == 4 # high
	not f.waived
	msg := sprintf("New high SAST finding %s in %s:%d", [f.rule_id, f.path, f.line])
}

# --- Tests -------------------------------------------------------------------

# A failing, non-quarantined test blocks.
deny contains msg if {
	some t in input.tests.failed
	not t.quarantined
	msg := sprintf("Failing test: %s / %s", [t.suite, t.name])
}

# --- Tool health -------------------------------------------------------------

# A check that errored did not run, so its family's coverage is unknown. Warn
# rather than silently passing (strict-release promotes this to deny).
warn contains msg if {
	some c in input.errored_checks
	msg := sprintf("Check %q errored and did not report; result is incomplete", [c])
}

# --- Coverage ----------------------------------------------------------------

# Warn when coverage of changed lines drops below 80%.
warn contains msg if {
	cov := input.metrics["coverage.changed_lines"]
	cov < 80
	msg := sprintf("Changed-lines coverage %.0f%% is below 80%%", [cov])
}
