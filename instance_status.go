package main

import (
	"slices"
	"sort"
	"strings"

	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
)

// A Go copy of the API's instance-status.ts, used only by the notification summary.
// Keep both in step; testdata/instance-status-cases.json is shared with the API tests.

const (
	hiddenContradicted = "contradicted"
	hiddenRetiredAll   = "retired_all"
)

// sourceOrigins puts OSV in its own origin and NVD and GCVE in the CVE List.
var sourceOrigins = map[string]string{"osv": "osv", "nvd": "cve_list", "gcve": "cve_list"}

func differentOrigins(a, b string) bool {
	originA, okA := sourceOrigins[a]
	originB, okB := sourceOrigins[b]
	return okA && okB && originA != originB
}

// instanceStatus says why an instance is hidden by default ("" when it is not) and which
// sources withdrew or contradicted one of its source matches.
func instanceStatus(verdicts []vulnerabilityFinder.SourceVerdict) (string, []string) {
	contradicting := []vulnerabilityFinder.Verdict{vulnerabilityFinder.VerdictVersionExcluded, vulnerabilityFinder.VerdictRetired, vulnerabilityFinder.VerdictNamesAnotherProduct}
	liveRecord := []vulnerabilityFinder.Verdict{vulnerabilityFinder.VerdictMatched, vulnerabilityFinder.VerdictVersionExcluded, vulnerabilityFinder.VerdictNamesAnotherProduct}

	matched, contradictedMatches, retired, live := 0, 0, false, false
	contradictedBy := []string{}
	for _, match := range verdicts {
		retired = retired || match.Verdict == vulnerabilityFinder.VerdictRetired
		live = live || slices.Contains(liveRecord, match.Verdict)
		if match.Verdict != vulnerabilityFinder.VerdictMatched {
			continue
		}
		matched++
		against := false
		for _, other := range verdicts {
			source := strings.ToLower(other.Source)
			if slices.Contains(contradicting, other.Verdict) && differentOrigins(strings.ToLower(match.Source), source) {
				against = true
				if !slices.Contains(contradictedBy, source) {
					contradictedBy = append(contradictedBy, source)
				}
			}
		}
		if against {
			contradictedMatches++
		}
	}
	sort.Strings(contradictedBy)

	if matched > 0 && contradictedMatches == matched {
		return hiddenContradicted, contradictedBy
	}
	if retired && !live {
		return hiddenRetiredAll, contradictedBy
	}
	return "", contradictedBy
}
