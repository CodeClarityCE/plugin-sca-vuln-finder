package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
)

// stubAdvisories gives no advisories, or fails every lookup with err.
type stubAdvisories struct{ err error }

func (s stubAdvisories) OSV(string) ([]knowledge_db.OSVItem, error)   { return nil, s.err }
func (s stubAdvisories) NVD(string) ([]knowledge_db.NVDItem, error)   { return nil, s.err }
func (s stubAdvisories) GCVE(string) ([]knowledge_db.GCVEItem, error) { return nil, s.err }

func analyzeJS(advisories stubAdvisories) (vulnerabilityFinder.Output, string) {
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{"left-pad": {"1.3.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}}
	return combineVulnOutputs(keys, func(sbomKey) (vulnerabilityFinder.Output, error) {
		return vulnerabilities.StartWithAdvisories("", sbom, "JS", time.Now(), nil, nil, advisories)
	}, time.Now())
}

func TestFailedKnowledgeLookupFailsTheStepWithAReadableReason(t *testing.T) {
	raw := errors.New(`pgdriver: SASL: read tcp 10.0.0.5:4242->pgbouncer:6432: i/o timeout SELECT DISTINCT "id" FROM nvd`)

	out, reason := analyzeJS(stubAdvisories{err: raw})

	if out.AnalysisInfo.Status != codeclarity.FAILURE {
		t.Fatalf("status = %s, want failure", out.AnalysisInfo.Status)
	}
	if reason != knowledgeLookupReason {
		t.Fatalf("reason = %q", reason)
	}
	for _, leak := range []string{"pgbouncer", "6432", "SELECT", "pgdriver"} {
		if strings.Contains(reason, leak) {
			t.Fatalf("reason %q leaks %q", reason, leak)
		}
	}
}

func TestPackageMissingFromKnowledgeStillSucceeds(t *testing.T) {
	out, reason := analyzeJS(stubAdvisories{})

	if out.AnalysisInfo.Status != codeclarity.SUCCESS || reason != "" {
		t.Fatalf("status = %s, reason = %q", out.AnalysisInfo.Status, reason)
	}
	if n := len(out.WorkSpaces["."].Vulnerabilities); n != 0 {
		t.Fatalf("got %d vulnerabilities", n)
	}
}
