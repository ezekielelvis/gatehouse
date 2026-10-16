# Gatehouse strict-release policy pack (plan §9).
#
# Layered ON TOP of baseline for release gates: select both in gatehouse.yaml:
#
#   policy_packs: [baseline, strict-release]
#
# It tightens the gate — things baseline only warns about become blocking, and
# release-only concerns (existing criticals, forbidden licences, incomplete
# runs) are enforced. All rules add to the same gatehouse.gates deny/warn sets.
package gatehouse.gates

import rego.v1

# Promote new high SAST findings from warn (baseline) to deny.
deny contains msg if {
	input.context == "release"
	some f in input.findings
	f.type == "sast"
	f.status == "new"
	f.severity_n == 4 # high
	not f.waived
	msg := sprintf("[strict] New high SAST finding %s in %s:%d blocks release", [f.rule_id, f.path, f.line])
}

# At release, even pre-existing critical findings block (no shipping known
# criticals), unless explicitly waived.
deny contains msg if {
	input.context == "release"
	some f in input.findings
	f.severity_n >= 5 # critical
	not f.waived
	msg := sprintf("[strict] Critical %s finding %s must be fixed or waived before release", [f.type, f.rule_id])
}

# Forbidden (strong copyleft / source-available) licences block a release.
forbidden_licences := {"AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0"}

deny contains msg if {
	input.context == "release"
	some c in input.sbom.components
	c.license in forbidden_licences
	msg := sprintf("[strict] Forbidden licence %s in component %s@%s", [c.license, c.name, c.version])
}

# An incomplete run (a check errored) must not be releasable.
deny contains msg if {
	input.context == "release"
	some c in input.errored_checks
	msg := sprintf("[strict] Check %q errored; a release gate requires every check to complete", [c])
}
