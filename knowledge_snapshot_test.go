package main

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleSnapshot() knowledge.KnowledgeSnapshot {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	outcome := knowledge.SourceSyncSuccess
	return knowledge.TakeSnapshot([]knowledge.SourceSync{
		{Source: knowledge.SourceOSV, Watermark: &now, LastOutcome: &outcome, RowCount: 42},
	}, now, nil)
}

func TestEveryVulnResultRecordsTheKnowledgeSnapshot(t *testing.T) {
	snapshot := sampleSnapshot()
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}}
	cases := map[string]struct {
		keys    []sbomKey
		analyze func(sbomKey) (vulnerabilityFinder.Output, error)
	}{
		"matched SBOMs": {keys, func(k sbomKey) (vulnerabilityFinder.Output, error) {
			return vulnOutput(codeclarity.SUCCESS, k.language), nil
		}},
		"no SBOM found": {nil, nil},
		"a failed SBOM": {keys, func(sbomKey) (vulnerabilityFinder.Output, error) {
			return vulnerabilityFinder.Output{}, errors.New("load failed")
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out, _ := buildVulnOutput(tc.keys, tc.analyze, time.Now(), snapshot)
			require.NotNil(t, out.AnalysisInfo.KnowledgeSnapshot)
			assert.Equal(t, snapshot, *out.AnalysisInfo.KnowledgeSnapshot)
		})
	}
}

func TestStoredVulnResultKeepsSnapshotAndSourceMatches(t *testing.T) {
	snapshot := sampleSnapshot()
	output := vulnOutput(codeclarity.SUCCESS, "js")
	output.AnalysisInfo.KnowledgeSnapshot = &snapshot
	output.WorkSpaces["js"] = vulnerabilityFinder.Workspace{Vulnerabilities: []vulnerabilityFinder.Vulnerability{{
		VulnerabilityId: "CVE-2024-0001",
		SourceMatches:   []vulnerabilityFinder.SourceMatch{{Source: knowledge.SourceNVD, RecordId: "CVE-2024-0001", Winning: true}},
	}}}

	stored, err := json.Marshal(vulnerabilityFinder.ConvertOutputToMap(output))
	require.NoError(t, err)
	var loaded vulnerabilityFinder.Output
	require.NoError(t, json.Unmarshal(stored, &loaded))

	require.NotNil(t, loaded.AnalysisInfo.KnowledgeSnapshot)
	osv := loaded.AnalysisInfo.KnowledgeSnapshot.Sources[len(loaded.AnalysisInfo.KnowledgeSnapshot.Sources)-1]
	assert.Equal(t, knowledge.SourceOSV, osv.Source)
	assert.Equal(t, int64(42), osv.RowCount)
	assert.True(t, osv.Comparable)
	assert.Equal(t, "CVE-2024-0001", loaded.WorkSpaces["js"].Vulnerabilities[0].SourceMatches[0].RecordId)
}

// olderVulnResult is the stored shape before analyses recorded source matches and a knowledge snapshot.
const olderVulnResult = `{
	"workspaces": {"." : {"Vulnerabilities": [{
		"Sources": ["OSV"], "AffectedDependency": "lodash", "AffectedVersion": "4.17.20",
		"VulnerabilityId": "CVE-2021-23337",
		"OSVMatch": {"Vulnerability": {"id": "GHSA-35jh-r3h4-6jhm"}},
		"Severity": {"Severity": 7.2}, "Weaknesses": [],
		"Conflict": {"ConflictWinner": "OSV", "ConflictFlag": "MATCH_CORRECT"}
	}]}},
	"analysis_info": {"status": "success", "errors": [], "analysis_start_time": "x"}
}`

func TestOlderVulnResultsWithoutSnapshotOrSourceMatchesStillLoad(t *testing.T) {
	var loaded vulnerabilityFinder.Output
	require.NoError(t, json.Unmarshal([]byte(olderVulnResult), &loaded))

	assert.Nil(t, loaded.AnalysisInfo.KnowledgeSnapshot)
	vulns := loaded.WorkSpaces["."].Vulnerabilities
	require.Len(t, vulns, 1)
	assert.Nil(t, vulns[0].SourceMatches)
	assert.Equal(t, "GHSA-35jh-r3h4-6jhm", vulns[0].OSVMatch.Vulnerability.OSVId)

	// Re-storing an older result does not invent empty fields.
	restored, err := json.Marshal(loaded)
	require.NoError(t, err)
	assert.NotContains(t, string(restored), "knowledge_snapshot")
	assert.NotContains(t, string(restored), "SourceMatches")
}
