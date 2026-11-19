package main

import (
	"context"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

const (
	cvss40Critical = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	cvss31Critical = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
)

// osvAdvisories serves one OSV advisory for left-pad below 2.0.0.
type osvAdvisories struct{ advisory knowledge_db.OSVItem }

func (a osvAdvisories) OSV(_ context.Context, purl string) ([]knowledge_db.OSVItem, error) {
	if purl != "pkg:npm/left-pad" {
		return nil, nil
	}
	advisory := a.advisory
	advisory.OSVId = "GHSA-aaaa-bbbb-cccc"
	advisory.Cve = "CVE-2024-0001"
	advisory.Affected = []knowledge_db.Affected{{
		Package: knowledge_db.OSVPackage{Name: "left-pad", Ecosystem: "npm"},
		Ranges: []knowledge_db.Range{{Type: "SEMVER", Events: []knowledge_db.Event{
			{Introduced: "0"}, {Fixed: "2.0.0"},
		}}},
	}}
	return []knowledge_db.OSVItem{advisory}, nil
}
func (osvAdvisories) NVD(context.Context, string) ([]knowledge_db.NVDItem, error)   { return nil, nil }
func (osvAdvisories) GCVE(context.Context, string) ([]knowledge_db.GCVEItem, error) { return nil, nil }

func analyzeLeftPad(t *testing.T, advisory knowledge_db.OSVItem) vulnerabilityFinder.Vulnerability {
	t.Helper()
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{"left-pad": {"1.3.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	out, err := vulnerabilities.StartWithAdvisories("", sbom, "JS", time.Now(), nil, nil, osvAdvisories{advisory})
	if err != nil {
		t.Fatal(err)
	}
	found := out.WorkSpaces["."].Vulnerabilities
	if len(found) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1", len(found))
	}
	return found[0]
}

func TestAnAdvisoryWithOnlyACVSS4VectorIsScoredAsCVSS4(t *testing.T) {
	finding := analyzeLeftPad(t, knowledge_db.OSVItem{
		Severity: []knowledge_db.Severity{{Type: "CVSS_V4", Score: cvss40Critical}},
	})

	if finding.Severity.SeverityType != vulnerabilityFinder.CVSS_V40 {
		t.Fatalf("type = %q, want CVSS_V40", finding.Severity.SeverityType)
	}
	if finding.Severity.Severity != 9.3 || finding.Severity.SeverityClass != vulnerabilityFinder.CRITICAL {
		t.Fatalf("severity = %v %s, want 9.3 CRITICAL", finding.Severity.Severity, finding.Severity.SeverityClass)
	}
	if finding.Severity.Vector != cvss40Critical {
		t.Fatalf("vector = %q", finding.Severity.Vector)
	}
	if finding.Severity.ConfidentialityImpact != "HIGH" {
		t.Fatalf("confidentiality = %q, want HIGH", finding.Severity.ConfidentialityImpact)
	}
}

func TestAnAdvisoryWithCVSS31AndCVSS4ShowsCVSS4AndKeepsCVSS31(t *testing.T) {
	finding := analyzeLeftPad(t, knowledge_db.OSVItem{
		Severity: []knowledge_db.Severity{
			{Type: "CVSS_V3", Score: cvss31Critical},
			{Type: "CVSS_V4", Score: cvss40Critical},
		},
	})

	if finding.Severity.SeverityType != vulnerabilityFinder.CVSS_V40 || finding.Severity.Severity != 9.3 {
		t.Fatalf("shown = %s %v, want CVSS_V40 9.3", finding.Severity.SeverityType, finding.Severity.Severity)
	}
	byType := map[vulnerabilityFinder.SeverityType]float64{}
	for _, vector := range finding.Severity.Vectors {
		byType[vector.Type] = vector.Score
	}
	if byType[vulnerabilityFinder.CVSS_V31] != 9.8 || byType[vulnerabilityFinder.CVSS_V40] != 9.3 {
		t.Fatalf("vectors = %+v, want CVSS_V31 9.8 and CVSS_V40 9.3", finding.Severity.Vectors)
	}
	if len(finding.SourceMatches) != 1 || len(finding.SourceMatches[0].Vectors) != 2 {
		t.Fatalf("source match vectors = %+v, want both", finding.SourceMatches)
	}
}

func TestAnAdvisoryWithoutAVectorUsesTheGHSASeverityWithoutAScore(t *testing.T) {
	finding := analyzeLeftPad(t, knowledge_db.OSVItem{
		DatabaseSpecific: map[string]any{"severity": "MODERATE"},
	})

	if finding.Severity.SeverityType != vulnerabilityFinder.GHSA_SEVERITY {
		t.Fatalf("type = %q, want GHSA", finding.Severity.SeverityType)
	}
	if finding.Severity.SeverityClass != vulnerabilityFinder.MEDIUM || finding.Severity.Severity != 0 {
		t.Fatalf("severity = %v %s, want MEDIUM with no score", finding.Severity.Severity, finding.Severity.SeverityClass)
	}
	if finding.SourceMatches[0].Severity == nil || finding.SourceMatches[0].Severity.Class != vulnerabilityFinder.MEDIUM {
		t.Fatalf("source match severity = %+v, want MEDIUM", finding.SourceMatches[0].Severity)
	}
}

func TestAnAdvisoryWithNeitherVectorNorGHSASeverityHasNone(t *testing.T) {
	finding := analyzeLeftPad(t, knowledge_db.OSVItem{})

	if finding.Severity.SeverityClass != vulnerabilityFinder.NONE {
		t.Fatalf("class = %s, want NONE", finding.Severity.SeverityClass)
	}
}
