package conflictResolver

import (
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types/conflict"
)

func TrustOSV(pairs vulnerabilityFinder.Pairs) (conflict.ResolveWinner, conflict.ConflictFlag) {
	if pairs.OSV.Vulnerability.Cve == "" {
		return conflict.NVD, conflict.MATCH_POSSIBLE_INCORRECT
	}
	return conflict.OSV, conflict.MATCH_CORRECT
}
