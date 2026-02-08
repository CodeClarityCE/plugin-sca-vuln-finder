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

// TrustGCVE prioritizes GCVE as the primary vulnerability source.
// Resolution order: GCVE > OSV > NVD.
func TrustGCVE(pairs vulnerabilityFinder.Pairs) (conflict.ResolveWinner, conflict.ConflictFlag) {
	hasGCVE := pairs.GCVE.Dependency.Name != ""
	hasOSV := pairs.OSV.Dependency.Name != ""
	hasNVD := pairs.NVD.Dependency.Name != ""

	if hasGCVE {
		return conflict.GCVE, conflict.MATCH_CORRECT
	}
	if hasOSV {
		if hasNVD {
			return conflict.OSV, conflict.MATCH_CORRECT
		}
		return conflict.OSV, conflict.MATCH_POSSIBLE_INCORRECT
	}
	if hasNVD {
		return conflict.NVD, conflict.MATCH_POSSIBLE_INCORRECT
	}
	return conflict.NONE, conflict.MATCH_NO_CONFLICT
}

// TrustOSVFirst prioritizes OSV as the primary vulnerability source.
// Resolution order: OSV > GCVE > NVD.
func TrustOSVFirst(pairs vulnerabilityFinder.Pairs) (conflict.ResolveWinner, conflict.ConflictFlag) {
	hasOSV := pairs.OSV.Dependency.Name != ""
	hasGCVE := pairs.GCVE.Dependency.Name != ""
	hasNVD := pairs.NVD.Dependency.Name != ""

	if hasOSV {
		return conflict.OSV, conflict.MATCH_CORRECT
	}
	if hasGCVE {
		if hasNVD {
			return conflict.GCVE, conflict.MATCH_CORRECT
		}
		return conflict.GCVE, conflict.MATCH_POSSIBLE_INCORRECT
	}
	if hasNVD {
		return conflict.NVD, conflict.MATCH_POSSIBLE_INCORRECT
	}
	return conflict.NONE, conflict.MATCH_NO_CONFLICT
}
