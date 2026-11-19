package main

import (
	"slices"
	"sort"
	"strings"

	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// A Go copy of the API's instance-status.ts, used only by the notification summary.
// testdata/instance-status-cases.json is shared with the API tests.

const (
	hiddenContradicted = "contradicted"
	hiddenRetiredAll   = "retired_all"
)

// sourceOrigins puts OSV in its own origin and NVD and GCVE in the CVE List.
var sourceOrigins = map[string]string{
	knowledge.SourceOSV:  "osv",
	knowledge.SourceNVD:  "cve_list",
	knowledge.SourceGCVE: "cve_list",
}

func differentOrigins(a, b string) bool {
	originA, okA := sourceOrigins[a]
	originB, okB := sourceOrigins[b]
	return okA && okB && originA != originB
}

// verdictTraits says whether a verdict denies a match of another origin and whether it holds a live record.
var verdictTraits = map[vulnerabilityFinder.Verdict]struct{ contradicts, liveRecord bool }{
	vulnerabilityFinder.VerdictMatched:             {false, true},
	vulnerabilityFinder.VerdictVersionExcluded:     {true, true},
	vulnerabilityFinder.VerdictRetired:             {true, false},
	vulnerabilityFinder.VerdictNamesAnotherProduct: {true, true},
}

// contradicts reports whether a verdict denies a match; naming another product counts only in the instance's ecosystem.
func contradicts(verdict vulnerabilityFinder.SourceVerdict, ecosystem string) bool {
	if !verdictTraits[verdict.Verdict].contradicts {
		return false
	}
	if verdict.Verdict != vulnerabilityFinder.VerdictNamesAnotherProduct {
		return true
	}
	if ecosystem == "" || verdict.Evidence == nil {
		return false
	}
	return slices.ContainsFunc(verdict.Evidence.Names, func(name vulnerabilityFinder.SourceProduct) bool {
		return strings.EqualFold(name.Ecosystem, ecosystem)
	})
}

// instanceStatus says why an instance is hidden by default ("" when it is not) and which
// sources withdrew or contradicted one of its source matches.
func instanceStatus(verdicts []vulnerabilityFinder.SourceVerdict, ecosystem string) (string, []string) {
	matched, contradictedMatches, retired, live := 0, 0, false, false
	contradictedBy := []string{}
	for _, match := range verdicts {
		retired = retired || match.Verdict == vulnerabilityFinder.VerdictRetired
		live = live || verdictTraits[match.Verdict].liveRecord
		if match.Verdict != vulnerabilityFinder.VerdictMatched {
			continue
		}
		matched++
		against := false
		for _, other := range verdicts {
			source := strings.ToLower(other.Source)
			if contradicts(other, ecosystem) && differentOrigins(strings.ToLower(match.Source), source) {
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
