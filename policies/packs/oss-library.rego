# oss-library policy pack (plan §9): the gate an open-source library should
# pass — a clean licence posture, an SBOM, and no secrets. Layer on baseline.
package gatehouse.gates

import rego.v1

# Copyleft / source-available licences that are usually incompatible with a
# permissively licensed library's dependency tree.
oss_forbidden_licences := {"AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "GPL-3.0-only"}

deny contains msg if {
	some c in input.sbom.components
	c.license in oss_forbidden_licences
	msg := sprintf("[oss-library] Forbidden licence %s in %s@%s", [c.license, c.name, c.version])
}

# A library release should ship an SBOM; warn if none was produced.
warn contains msg if {
	input.context == "release"
	count(input.sbom.components) == 0
	msg := "[oss-library] No SBOM produced for this release"
}
