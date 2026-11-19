package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// leftPadAdvisories serves an OSV advisory for left-pad and, when withNVD is set, the NVD record of the same CVE.
type leftPadAdvisories struct{ withNVD bool }

func (leftPadAdvisories) OSVByID(context.Context, []string) ([]knowledge.OSVItem, error) {
	return nil, nil
}
func (leftPadAdvisories) NVDByID(context.Context, []string) ([]knowledge.NVDItem, error) {
	return nil, nil
}
func (leftPadAdvisories) GCVEByID(context.Context, []string) ([]knowledge.GCVEItem, error) {
	return nil, nil
}

func (leftPadAdvisories) OSV(ctx context.Context, purl string) ([]knowledge.OSVItem, error) {
	return osvAdvisories{}.OSV(ctx, purl)
}
func (a leftPadAdvisories) NVD(_ context.Context, name string) ([]knowledge.NVDItem, error) {
	if !a.withNVD || name != "left-pad" {
		return nil, nil
	}
	record := leftPadNVDRecord("A flaw in left-pad.")
	record.NVDId = "CVE-2024-0001"
	return []knowledge.NVDItem{record}, nil
}
func (leftPadAdvisories) GCVE(context.Context, string) ([]knowledge.GCVEItem, error) {
	return nil, nil
}

var verdictsNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// snapshotWith makes osv and nvd healthy and gives gcve the sync row passed.
func snapshotWith(gcve knowledge.SourceSync) *knowledge.KnowledgeSnapshot {
	success := knowledge.SourceSyncSuccess
	gcve.Source = knowledge.SourceGCVE
	snapshot := knowledge.TakeSnapshot([]knowledge.SourceSync{
		{Source: knowledge.SourceOSV, Watermark: &verdictsNow, LastOutcome: &success},
		{Source: knowledge.SourceNVD, Watermark: &verdictsNow, LastOutcome: &success},
		gcve,
	}, verdictsNow, nil)
	return &snapshot
}

func verdictsFor(t *testing.T, advisories leftPadAdvisories, snapshot *knowledge.KnowledgeSnapshot) map[string]vulnerabilityFinder.SourceVerdict {
	t.Helper()
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{"left-pad": {"1.3.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	out, err := vulnerabilities.StartWithKnowledge("", sbom, "JS", time.Now(), nil, nil, snapshot, advisories)
	require.NoError(t, err)
	found := out.WorkSpaces["."].Vulnerabilities
	require.Len(t, found, 1)
	require.Len(t, found[0].SourceVerdicts, 3, "one verdict per knowledge source")
	bySource := map[string]vulnerabilityFinder.SourceVerdict{}
	for _, verdict := range found[0].SourceVerdicts {
		bySource[verdict.Source] = verdict
	}
	return bySource
}

func TestEverySourceGetsAVerdictForAnInstance(t *testing.T) {
	failure := knowledge.SourceSyncFailure
	verdicts := verdictsFor(t, leftPadAdvisories{withNVD: true}, snapshotWith(knowledge.SourceSync{Watermark: &verdictsNow, LastOutcome: &failure}))

	assert.Equal(t, vulnerabilityFinder.VerdictMatched, verdicts[knowledge.SourceOSV].Verdict)
	assert.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, verdicts[knowledge.SourceOSV].Evidence.RecordIds)
	assert.Equal(t, vulnerabilityFinder.VerdictMatched, verdicts[knowledge.SourceNVD].Verdict)
	assert.Equal(t, vulnerabilityFinder.VerdictStaleOrFailed, verdicts[knowledge.SourceGCVE].Verdict)
	assert.Equal(t, knowledge.SourceFailed, verdicts[knowledge.SourceGCVE].Evidence.SourceStatus)
}

func TestAHealthySourceWithoutAMatchSaysNoRecord(t *testing.T) {
	success := knowledge.SourceSyncSuccess
	verdicts := verdictsFor(t, leftPadAdvisories{}, snapshotWith(knowledge.SourceSync{Watermark: &verdictsNow, LastOutcome: &success}))

	assert.Equal(t, vulnerabilityFinder.VerdictMatched, verdicts[knowledge.SourceOSV].Verdict)
	assert.Equal(t, vulnerabilityFinder.VerdictNoRecord, verdicts[knowledge.SourceNVD].Verdict)
	assert.Nil(t, verdicts[knowledge.SourceNVD].Evidence)
	assert.Equal(t, vulnerabilityFinder.VerdictNoRecord, verdicts[knowledge.SourceGCVE].Verdict)
}

func TestAStaleSourceWithoutAMatchSaysStaleOrFailed(t *testing.T) {
	success := knowledge.SourceSyncSuccess
	weekAgo := verdictsNow.AddDate(0, 0, -7)
	verdicts := verdictsFor(t, leftPadAdvisories{}, snapshotWith(knowledge.SourceSync{Watermark: &weekAgo, LastOutcome: &success}))

	assert.Equal(t, vulnerabilityFinder.VerdictNoRecord, verdicts[knowledge.SourceNVD].Verdict)
	assert.Equal(t, vulnerabilityFinder.VerdictStaleOrFailed, verdicts[knowledge.SourceGCVE].Verdict)
	assert.Equal(t, knowledge.SourceStale, verdicts[knowledge.SourceGCVE].Evidence.SourceStatus)
}

func TestWithoutASnapshotUnmatchedSourcesAreStaleOrFailed(t *testing.T) {
	verdicts := verdictsFor(t, leftPadAdvisories{}, nil)

	assert.Equal(t, vulnerabilityFinder.VerdictMatched, verdicts[knowledge.SourceOSV].Verdict)
	assert.Equal(t, vulnerabilityFinder.VerdictStaleOrFailed, verdicts[knowledge.SourceNVD].Verdict)
	assert.Equal(t, knowledge.SourceUnknown, verdicts[knowledge.SourceNVD].Evidence.SourceStatus)
}

func TestStoredVerdictsRoundTripAndOlderResultsHaveNone(t *testing.T) {
	stored, err := json.Marshal(vulnerabilityFinder.Vulnerability{SourceVerdicts: []vulnerabilityFinder.SourceVerdict{
		{Source: knowledge.SourceNVD, Verdict: vulnerabilityFinder.VerdictNoRecord},
	}})
	require.NoError(t, err)
	assert.Contains(t, string(stored), `"SourceVerdicts":[{"source":"nvd","verdict":"no_record"}]`)

	var older vulnerabilityFinder.Output
	require.NoError(t, json.Unmarshal([]byte(olderVulnResult), &older))
	assert.Nil(t, older.WorkSpaces["."].Vulnerabilities[0].SourceVerdicts)
	restored, err := json.Marshal(older)
	require.NoError(t, err)
	assert.NotContains(t, string(restored), "SourceVerdicts")
}
