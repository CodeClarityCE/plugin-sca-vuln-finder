package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evidenceAdvisories serves left-pad records by package and any records by vulnerability ID.
type evidenceAdvisories struct {
	osv      []knowledge.OSVItem
	nvd      []knowledge.NVDItem
	gcve     []knowledge.GCVEItem
	osvByID  []knowledge.OSVItem
	nvdByID  []knowledge.NVDItem
	gcveByID []knowledge.GCVEItem
	byIDErr  error
}

func (a evidenceAdvisories) OSV(_ context.Context, purl string) ([]knowledge.OSVItem, error) {
	if purl != "pkg:npm/left-pad" {
		return nil, nil
	}
	return a.osv, nil
}
func (a evidenceAdvisories) NVD(_ context.Context, product string) ([]knowledge.NVDItem, error) {
	if product != "left-pad" {
		return nil, nil
	}
	return a.nvd, nil
}
func (a evidenceAdvisories) GCVE(_ context.Context, product string) ([]knowledge.GCVEItem, error) {
	if product != "left-pad" {
		return nil, nil
	}
	return a.gcve, nil
}
func (a evidenceAdvisories) OSVByID(_ context.Context, ids []string) ([]knowledge.OSVItem, error) {
	return keepAsked(a.osvByID, ids, a.byIDErr, func(r knowledge.OSVItem) []string { return append([]string{r.OSVId, r.Cve}, r.Aliases...) })
}
func (a evidenceAdvisories) NVDByID(_ context.Context, ids []string) ([]knowledge.NVDItem, error) {
	return keepAsked(a.nvdByID, ids, a.byIDErr, func(r knowledge.NVDItem) []string { return []string{r.NVDId} })
}
func (a evidenceAdvisories) GCVEByID(_ context.Context, ids []string) ([]knowledge.GCVEItem, error) {
	return keepAsked(a.gcveByID, ids, a.byIDErr, func(r knowledge.GCVEItem) []string { return []string{r.GCVEId, r.CVEId} })
}

// keepAsked returns the records one of whose IDs was asked for.
func keepAsked[T any](records []T, asked []string, err error, idsOf func(T) []string) ([]T, error) {
	if err != nil {
		return nil, err
	}
	kept := []T{}
	for _, record := range records {
		if slices.ContainsFunc(idsOf(record), func(id string) bool { return id != "" && slices.Contains(asked, id) }) {
			kept = append(kept, record)
		}
	}
	return kept, nil
}

const evidenceCVE = "CVE-2024-0001"

// matchingNVD is an NVD record of evidenceCVE that matches left-pad 1.3.0.
func matchingNVD() knowledge.NVDItem {
	record := leftPadNVDRecord("A flaw in left-pad.")
	record.NVDId = evidenceCVE
	return record
}

// matchingOSV is an OSV advisory of evidenceCVE that matches left-pad 1.3.0.
func matchingOSV() knowledge.OSVItem {
	return leftPadOSV("GHSA-1111-2222-3333", knowledge.Range{Type: "SEMVER", Events: []knowledge.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}})
}

func leftPadOSV(id string, ranges ...knowledge.Range) knowledge.OSVItem {
	return knowledge.OSVItem{
		OSVId:     id,
		Aliases:   []string{evidenceCVE},
		Published: "2024-01-01T00:00:00Z",
		Affected: []knowledge.Affected{{
			Package: knowledge.OSVPackage{Ecosystem: "npm", Name: "left-pad", Purl: "pkg:npm/left-pad"},
			Ranges:  ranges,
		}},
	}
}

func evidenceVerdicts(t *testing.T, advisories evidenceAdvisories) map[string]vulnerabilityFinder.SourceVerdict {
	t.Helper()
	out, err := analyzeLeftPadWith(advisories)
	require.NoError(t, err)
	found := out.WorkSpaces["."].Vulnerabilities
	require.Len(t, found, 1)
	require.Equal(t, evidenceCVE, found[0].VulnerabilityId)
	bySource := map[string]vulnerabilityFinder.SourceVerdict{}
	for _, verdict := range found[0].SourceVerdicts {
		bySource[verdict.Source] = verdict
	}
	require.Len(t, bySource, 3)
	return bySource
}

func analyzeLeftPadWith(advisories matcher.Advisories) (vulnerabilityFinder.Output, error) {
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{"left-pad": {"1.3.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	return vulnerabilities.StartWithKnowledge("", sbom, "JS", time.Now(), nil, nil, snapshotWith(knowledge.SourceSync{Watermark: &verdictsNow, LastOutcome: ptr(knowledge.SourceSyncSuccess)}), advisories)
}

func ptr[T any](v T) *T { return &v }

func TestAnOSVBranchFixCoveringTheVersionGivesVersionExcludedWithTheRanges(t *testing.T) {
	branchFix := leftPadOSV("GHSA-aaaa-bbbb-cccc",
		knowledge.Range{Type: "SEMVER", Events: []knowledge.Event{{Introduced: "0"}, {Fixed: "1.2.4"}}},
		knowledge.Range{Type: "SEMVER", Events: []knowledge.Event{{Introduced: "2.0.0"}, {Fixed: "2.1.0"}}},
	)

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{branchFix}, nvd: []knowledge.NVDItem{matchingNVD()}})

	osv := verdicts[knowledge.SourceOSV]
	assert.Equal(t, vulnerabilityFinder.VerdictVersionExcluded, osv.Verdict)
	require.NotNil(t, osv.Evidence)
	assert.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, osv.Evidence.RecordIds)
	require.NotNil(t, osv.Evidence.Evaluated)
	assert.Equal(t, []vulnerabilityFinder.SourceRange{{Fixed: "1.2.4"}, {Introduced: "2.0.0", Fixed: "2.1.0"}}, osv.Evidence.Evaluated.Ranges)
	assert.Equal(t, vulnerabilityFinder.VerdictMatched, verdicts[knowledge.SourceNVD].Verdict)
}

func TestAWithdrawnOSVAdvisoryGivesRetiredWithTheReasonAndDate(t *testing.T) {
	withdrawn := matchingOSV()
	withdrawn.Withdrawn = "2025-03-01T10:00:00Z"

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{withdrawn}, nvd: []knowledge.NVDItem{matchingNVD()}})

	osv := verdicts[knowledge.SourceOSV]
	assert.Equal(t, vulnerabilityFinder.VerdictRetired, osv.Verdict)
	require.NotNil(t, osv.Evidence)
	assert.Equal(t, []string{"GHSA-1111-2222-3333"}, osv.Evidence.RecordIds)
	assert.Equal(t, knowledge.RetiredWithdrawn, osv.Evidence.RetiredReason)
	assert.Equal(t, "2025-03-01T10:00:00Z", osv.Evidence.RetiredAt)
}

func TestARetiredNVDRecordGivesRetiredWithTheReasonAndDate(t *testing.T) {
	rejected := matchingNVD()
	rejected.RetiredReason = knowledge.RetiredRejected
	rejected.RetiredAt = time.Date(2025, 4, 2, 0, 0, 0, 0, time.UTC)

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, nvd: []knowledge.NVDItem{rejected}})

	nvd := verdicts[knowledge.SourceNVD]
	assert.Equal(t, vulnerabilityFinder.VerdictRetired, nvd.Verdict)
	assert.Equal(t, knowledge.RetiredRejected, nvd.Evidence.RetiredReason)
	assert.Equal(t, "2025-04-02T00:00:00Z", nvd.Evidence.RetiredAt)
}

func TestAGCVEUnaffectedEntryGivesVersionExcludedWithTheEntry(t *testing.T) {
	record := knowledge.GCVEItem{
		CVEId:         evidenceCVE,
		DatePublished: "2024-01-01T00:00:00Z",
		Affected: []knowledge.GCVEAffected{{
			Vendor: "left-pad_project", Product: "left-pad", DefaultStatus: "unaffected",
			Versions: []knowledge.GCVEVersion{affected("1.0.0", "2.0.0"), unaffected("1.3.0")},
		}},
		References: []knowledge.GCVEReference{{URL: "https://www.npmjs.com/package/left-pad"}},
	}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, gcve: []knowledge.GCVEItem{record}})

	gcve := verdicts[knowledge.SourceGCVE]
	assert.Equal(t, vulnerabilityFinder.VerdictVersionExcluded, gcve.Verdict)
	assert.Equal(t, []string{evidenceCVE}, gcve.Evidence.RecordIds)
	assert.Equal(t, []vulnerabilityFinder.SourceRange{{Introduced: "1.0.0", Fixed: "2.0.0"}}, gcve.Evidence.Evaluated.Ranges)
	require.NotNil(t, gcve.Evidence.Unaffected)
	assert.Equal(t, []vulnerabilityFinder.SourceRange{{Introduced: "1.3.0", Fixed: "2.0.0"}}, gcve.Evidence.Unaffected.Ranges)
}

func TestAGCVEUnaffectedComparatorGivesVersionExcludedWithItsBounds(t *testing.T) {
	record := knowledge.GCVEItem{
		CVEId:         evidenceCVE,
		DatePublished: "2024-01-01T00:00:00Z",
		Affected: []knowledge.GCVEAffected{{
			Vendor: "left-pad_project", Product: "left-pad", DefaultStatus: "unaffected",
			Versions: []knowledge.GCVEVersion{affected("1.0.0", "2.0.0"), unaffected(">= 1.2.0, < 1.4.0")},
		}},
		References: []knowledge.GCVEReference{{URL: "https://www.npmjs.com/package/left-pad"}},
	}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, gcve: []knowledge.GCVEItem{record}})

	gcve := verdicts[knowledge.SourceGCVE]
	assert.Equal(t, vulnerabilityFinder.VerdictVersionExcluded, gcve.Verdict)
	require.NotNil(t, gcve.Evidence.Unaffected)
	assert.Equal(t, []vulnerabilityFinder.SourceRange{{Introduced: "1.2.0", Fixed: "1.4.0"}}, gcve.Evidence.Unaffected.Ranges)
}

func TestAGCVERecordForAnotherProductOfTheSameNameGivesNamesAnotherProduct(t *testing.T) {
	plugin := knowledge.GCVEItem{
		CVEId:         evidenceCVE,
		DatePublished: "2024-01-01T00:00:00Z",
		Affected: []knowledge.GCVEAffected{{
			Vendor: "Acme Themes", Product: "left-pad", DefaultStatus: "unaffected",
			Versions: []knowledge.GCVEVersion{affected("0", "2.0.0")},
		}},
		References: []knowledge.GCVEReference{{URL: "https://wordpress.org/plugins/left-pad/"}},
	}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, gcve: []knowledge.GCVEItem{plugin}})

	gcve := verdicts[knowledge.SourceGCVE]
	assert.Equal(t, vulnerabilityFinder.VerdictNamesAnotherProduct, gcve.Verdict)
	assert.Equal(t, []vulnerabilityFinder.SourceProduct{{Vendor: "Acme Themes", Product: "left-pad"}}, gcve.Evidence.Names)
}

func TestAnNVDRecordForAnotherProductOfTheSameNameGivesNamesAnotherProduct(t *testing.T) {
	record := matchingNVD()
	record.Affected = []knowledge.NVDAffected{{Sources: []knowledge.Sources{{
		Vulnerable:          true,
		Criteria:            "cpe:2.3:a:acme:left-pad:*:*:*:*:*:wordpress:*:*",
		VersionEndExcluding: "2.0.0",
		CriteriaDict:        knowledge.CriteriaDict{Part: "a", Vendor: "acme", Product: "left-pad", TargetSw: "wordpress"},
	}}}}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, nvd: []knowledge.NVDItem{record}})

	nvd := verdicts[knowledge.SourceNVD]
	assert.Equal(t, vulnerabilityFinder.VerdictNamesAnotherProduct, nvd.Verdict)
	assert.Equal(t, []string{evidenceCVE}, nvd.Evidence.RecordIds)
	assert.Equal(t, []vulnerabilityFinder.SourceProduct{{Vendor: "acme", Product: "left-pad", TargetSw: "wordpress"}}, nvd.Evidence.Names)
}

func TestARecordOfTheSameCVEFoundOnlyByIDNamesAnotherProduct(t *testing.T) {
	cli := knowledge.GCVEItem{
		GCVEId: "GCVE-1-2024-0001", CVEId: evidenceCVE,
		Affected: []knowledge.GCVEAffected{{Vendor: "acme", Product: "leftpad-cli"}},
	}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, gcveByID: []knowledge.GCVEItem{cli}})

	gcve := verdicts[knowledge.SourceGCVE]
	assert.Equal(t, vulnerabilityFinder.VerdictNamesAnotherProduct, gcve.Verdict)
	assert.Equal(t, []string{"GCVE-1-2024-0001"}, gcve.Evidence.RecordIds)
	assert.Equal(t, []vulnerabilityFinder.SourceProduct{{Vendor: "acme", Product: "leftpad-cli"}}, gcve.Evidence.Names)
}

func TestAnUnreviewedAdvisoryWithNoPackageDataGivesNoPackageData(t *testing.T) {
	unreviewed := knowledge.OSVItem{OSVId: "GHSA-9999-8888-7777", Aliases: []string{evidenceCVE}}
	awaiting := knowledge.NVDItem{NVDId: "CVE-2024-0002", VulnStatus: "Awaiting Analysis"}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{
		nvd:     []knowledge.NVDItem{matchingNVD()},
		osvByID: []knowledge.OSVItem{unreviewed},
		nvdByID: []knowledge.NVDItem{awaiting},
	})

	osv := verdicts[knowledge.SourceOSV]
	assert.Equal(t, vulnerabilityFinder.VerdictNoPackageData, osv.Verdict)
	assert.Equal(t, []string{"GHSA-9999-8888-7777"}, osv.Evidence.RecordIds)
	assert.Equal(t, vulnerabilityFinder.VerdictMatched, verdicts[knowledge.SourceNVD].Verdict)
}

func TestAnOSVRecordOfTheSameCVEForAnotherPackageNamesThatPackage(t *testing.T) {
	other := knowledge.OSVItem{OSVId: "GHSA-4444-5555-6666", Aliases: []string{evidenceCVE}, Affected: []knowledge.Affected{{
		Package: knowledge.OSVPackage{Ecosystem: "PyPI", Name: "left-pad"},
	}}}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{nvd: []knowledge.NVDItem{matchingNVD()}, osvByID: []knowledge.OSVItem{other}})

	osv := verdicts[knowledge.SourceOSV]
	assert.Equal(t, vulnerabilityFinder.VerdictNamesAnotherProduct, osv.Verdict)
	assert.Equal(t, []vulnerabilityFinder.SourceProduct{{Ecosystem: "PyPI", Package: "left-pad"}}, osv.Evidence.Names)
}

func TestAMatchOutranksAnyOtherRecordOfTheSameSource(t *testing.T) {
	excluded := leftPadOSV("GHSA-aaaa-bbbb-cccc", knowledge.Range{Type: "SEMVER", Events: []knowledge.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}})

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV(), excluded}})

	osv := verdicts[knowledge.SourceOSV]
	assert.Equal(t, vulnerabilityFinder.VerdictMatched, osv.Verdict)
	assert.Equal(t, []string{"GHSA-1111-2222-3333"}, osv.Evidence.RecordIds)
	assert.Equal(t, vulnerabilityFinder.VerdictNoRecord, verdicts[knowledge.SourceGCVE].Verdict)
}

func TestAFailedLookupByIDFailsTheStep(t *testing.T) {
	_, err := analyzeLeftPadWith(evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, byIDErr: errors.New("connection reset")})

	require.ErrorIs(t, err, matcher.ErrKnowledgeLookup)
}

func TestAnInstanceCarriesItsOSVEcosystem(t *testing.T) {
	out, err := analyzeLeftPadWith(evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}})
	require.NoError(t, err)

	require.Len(t, out.WorkSpaces["."].Vulnerabilities, 1)
	assert.Equal(t, "npm", out.WorkSpaces["."].Vulnerabilities[0].Ecosystem)
}

func TestAnNVDRecordNamingANodeJSProductNamesItInTheNpmEcosystem(t *testing.T) {
	cli := knowledge.NVDItem{NVDId: evidenceCVE, Affected: []knowledge.NVDAffected{{Sources: []knowledge.Sources{{
		Vulnerable:   true,
		Criteria:     "cpe:2.3:a:acme:leftpad-cli:*:*:*:*:*:node.js:*:*",
		CriteriaDict: knowledge.CriteriaDict{Part: "a", Vendor: "acme", Product: "leftpad-cli", TargetSw: "node.js"},
	}}}}}

	verdicts := evidenceVerdicts(t, evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, nvdByID: []knowledge.NVDItem{cli}})

	nvd := verdicts[knowledge.SourceNVD]
	assert.Equal(t, vulnerabilityFinder.VerdictNamesAnotherProduct, nvd.Verdict)
	assert.Equal(t, []vulnerabilityFinder.SourceProduct{{Ecosystem: "npm", Vendor: "acme", Product: "leftpad-cli", TargetSw: "node.js"}}, nvd.Evidence.Names)
}

func TestAGHSAMatchStaysVisibleWhenNVDNamesAnUpstreamProduct(t *testing.T) {
	upstream := knowledge.NVDItem{NVDId: evidenceCVE, Affected: []knowledge.NVDAffected{{Sources: []knowledge.Sources{{
		Vulnerable:   true,
		Criteria:     "cpe:2.3:a:gnu:libpad:*:*:*:*:*:*:*:*",
		CriteriaDict: knowledge.CriteriaDict{Part: "a", Vendor: "gnu", Product: "libpad", TargetSw: "*"},
	}}}}}

	out, err := analyzeLeftPadWith(evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, nvdByID: []knowledge.NVDItem{upstream}})
	require.NoError(t, err)

	found := out.WorkSpaces["."].Vulnerabilities[0]
	hidden, contradictedBy := instanceStatus(found.SourceVerdicts, found.Ecosystem)
	assert.Equal(t, "", hidden)
	assert.Empty(t, contradictedBy)
}

func TestAGHSAMatchIsHiddenWhenNVDNamesAnotherNpmPackage(t *testing.T) {
	other := knowledge.NVDItem{NVDId: evidenceCVE, Affected: []knowledge.NVDAffected{{Sources: []knowledge.Sources{{
		Vulnerable:   true,
		Criteria:     "cpe:2.3:a:acme:leftpad-cli:*:*:*:*:*:node.js:*:*",
		CriteriaDict: knowledge.CriteriaDict{Part: "a", Vendor: "acme", Product: "leftpad-cli", TargetSw: "node.js"},
	}}}}}

	out, err := analyzeLeftPadWith(evidenceAdvisories{osv: []knowledge.OSVItem{matchingOSV()}, nvdByID: []knowledge.NVDItem{other}})
	require.NoError(t, err)

	found := out.WorkSpaces["."].Vulnerabilities[0]
	hidden, contradictedBy := instanceStatus(found.SourceVerdicts, found.Ecosystem)
	assert.Equal(t, hiddenContradicted, hidden)
	assert.Equal(t, []string{knowledge.SourceNVD}, contradictedBy)
}
