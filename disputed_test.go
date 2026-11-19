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
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nvdAdvisories serves one NVD record for left-pad and nothing from the other sources.
type nvdAdvisories struct{ record knowledge_db.NVDItem }

func (nvdAdvisories) OSV(context.Context, string) ([]knowledge_db.OSVItem, error) { return nil, nil }
func (n nvdAdvisories) NVD(_ context.Context, name string) ([]knowledge_db.NVDItem, error) {
	if name != "left-pad" {
		return nil, nil
	}
	return []knowledge_db.NVDItem{n.record}, nil
}
func (nvdAdvisories) GCVE(context.Context, string) ([]knowledge_db.GCVEItem, error) {
	return nil, nil
}

func leftPadNVDRecord(description string) knowledge_db.NVDItem {
	return knowledge_db.NVDItem{
		NVDId:        "CVE-2024-4242",
		Published:    "2024-01-01T00:00:00Z",
		Descriptions: []knowledge_db.Descriptions{{Lang: "en", Value: description}},
		Affected: []knowledge_db.NVDAffected{{Sources: []knowledge_db.Sources{{
			Vulnerable:            true,
			Criteria:              "cpe:2.3:a:left-pad_project:left-pad:*:*:*:*:*:node.js:*:*",
			VersionStartIncluding: "1.0.0",
			VersionEndExcluding:   "1.4.0",
			CriteriaDict:          knowledge_db.CriteriaDict{Part: "a", Vendor: "left-pad_project", Product: "left-pad", TargetSw: "node.js"},
		}}}},
	}
}

func analyzeWithNVD(t *testing.T, description string) vulnerabilityFinder.Vulnerability {
	t.Helper()
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{"left-pad": {"1.3.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	out, err := vulnerabilities.StartWithAdvisories("", sbom, "JS", time.Now(), nil, nil, nvdAdvisories{leftPadNVDRecord(description)})
	require.NoError(t, err)
	vulns := out.WorkSpaces["."].Vulnerabilities
	require.Len(t, vulns, 1)
	return vulns[0]
}

func TestNVDRecordMarkedDisputedGivesADisputedInstance(t *testing.T) {
	vuln := analyzeWithNVD(t, "** DISPUTED ** left-pad 1.3.0 allows prototype pollution. NOTE: the maintainer states this is intended behavior.")

	assert.True(t, vuln.Disputed)
}

func TestNVDRecordWhoseNoteSaysTheVendorDisputesItGivesADisputedInstance(t *testing.T) {
	vuln := analyzeWithNVD(t, "left-pad before 1.4.0 allows ReDoS via a long string. NOTE: the vendor disputes this because the input is trusted.")

	assert.True(t, vuln.Disputed)
}

func TestUndisputedNVDRecordIsNotDisputed(t *testing.T) {
	vuln := analyzeWithNVD(t, "left-pad before 1.4.0 allows ReDoS via a long string.")

	assert.False(t, vuln.Disputed)
	stored, err := json.Marshal(vuln)
	require.NoError(t, err)
	assert.NotContains(t, string(stored), "Disputed", "older readers see no new field")
}
