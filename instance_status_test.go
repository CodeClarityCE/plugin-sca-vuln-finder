package main

import (
	"encoding/json"
	"os"
	"testing"

	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The cases are a copy of the API's instance-status.cases.json, so both rules agree.
func TestInstanceStatusMatchesTheAPIRule(t *testing.T) {
	raw, err := os.ReadFile("testdata/instance-status-cases.json")
	require.NoError(t, err)
	var cases []struct {
		Name           string                              `json:"name"`
		Verdicts       []vulnerabilityFinder.SourceVerdict `json:"verdicts"`
		Hidden         *string                             `json:"hidden"`
		ContradictedBy []string                            `json:"contradicted_by"`
	}
	require.NoError(t, json.Unmarshal(raw, &cases))
	require.NotEmpty(t, cases)

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			hidden, contradictedBy := instanceStatus(c.Verdicts)
			want := ""
			if c.Hidden != nil {
				want = *c.Hidden
			}
			assert.Equal(t, want, hidden)
			assert.Equal(t, c.ContradictedBy, contradictedBy)
		})
	}
}

func instance(id, dependency string, score float64, class vulnerabilityFinder.CVSS_CLASSV3, verdicts ...vulnerabilityFinder.SourceVerdict) vulnerabilityFinder.Vulnerability {
	return vulnerabilityFinder.Vulnerability{
		VulnerabilityId:    id,
		AffectedDependency: dependency,
		AffectedVersion:    "1.0.0",
		Severity:           vulnerabilityFinder.VulnerabilityMatchSeverity{Severity: score, SeverityClass: class},
		SourceVerdicts:     verdicts,
	}
}

func verdict(source string, v vulnerabilityFinder.Verdict) vulnerabilityFinder.SourceVerdict {
	return vulnerabilityFinder.SourceVerdict{Source: source, Verdict: v}
}

func TestNotificationSummaryLeavesHiddenInstancesOut(t *testing.T) {
	matched, excluded, retired := vulnerabilityFinder.VerdictMatched, vulnerabilityFinder.VerdictVersionExcluded, vulnerabilityFinder.VerdictRetired
	workspaces := map[string]vulnerabilityFinder.Workspace{
		".": {Vulnerabilities: []vulnerabilityFinder.Vulnerability{
			// Contradicted by a GHSA backport fix and by a GHSA withdrawal.
			instance("CVE-1", "lodash", 9.8, "CRITICAL", verdict("gcve", matched), verdict("osv", excluded)),
			instance("CVE-2", "axios", 9.1, "CRITICAL", verdict("gcve", matched), verdict("nvd", matched), verdict("osv", retired)),
			// Retired on all sources.
			instance("CVE-3", "qs", 7.5, "HIGH", verdict("gcve", retired), verdict("nvd", retired), verdict("osv", retired)),
			// Contradicted only by a source of the same origin, so still shown.
			instance("CVE-4", "minimist", 5.0, "MEDIUM", verdict("nvd", matched), verdict("gcve", excluded)),
			// An older result without verdicts hides nothing.
			instance("CVE-5", "express", 7.5, "HIGH"),
		}},
	}

	summary := buildVulnSummary(workspaces)

	assert.Equal(t, 2, summary.Total)
	assert.Equal(t, map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "NONE": 0}, summary.SeverityCounts)
	assert.Equal(t, "HIGH", summary.MaxSeverity)
	assert.Equal(t, map[string]int{"contradicted": 2, "retired_all": 1}, summary.HiddenCounts)
	require.Len(t, summary.Top, 2)
	assert.Equal(t, "CVE-5", summary.Top[0].VulnerabilityId)
	assert.Equal(t, "CVE-4", summary.Top[1].VulnerabilityId)
}
