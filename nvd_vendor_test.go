package main

import (
	"context"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/require"
)

// productAdvisories serves NVD records by the CPE product they are looked up with.
type productAdvisories map[string][]knowledge_db.NVDItem

func (productAdvisories) OSVByID(context.Context, []string) ([]knowledge_db.OSVItem, error) {
	return nil, nil
}
func (productAdvisories) NVDByID(context.Context, []string) ([]knowledge_db.NVDItem, error) {
	return nil, nil
}
func (productAdvisories) GCVEByID(context.Context, []string) ([]knowledge_db.GCVEItem, error) {
	return nil, nil
}

func (productAdvisories) OSV(context.Context, string) ([]knowledge_db.OSVItem, error) {
	return nil, nil
}
func (p productAdvisories) NVD(_ context.Context, product string) ([]knowledge_db.NVDItem, error) {
	return p[product], nil
}
func (productAdvisories) GCVE(context.Context, string) ([]knowledge_db.GCVEItem, error) {
	return nil, nil
}

// nodeCVE is an NVD record for vendor:product on node.js, affecting 0.1.0 up to 1.0.0.
func nodeCVE(id, vendor, product string, referenceURLs ...string) knowledge_db.NVDItem {
	references := []knowledge_db.References{}
	for _, url := range referenceURLs {
		references = append(references, knowledge_db.References{URL: url})
	}
	return knowledge_db.NVDItem{
		NVDId:        id,
		Published:    "2024-01-01T00:00:00Z",
		Descriptions: []knowledge_db.Descriptions{{Lang: "en", Value: "A session fixation issue."}},
		References:   references,
		Affected: []knowledge_db.NVDAffected{{Sources: []knowledge_db.Sources{{
			Vulnerable:            true,
			Criteria:              "cpe:2.3:a:" + vendor + ":" + product + ":*:*:*:*:*:node.js:*:*",
			VersionStartIncluding: "0.1.0",
			VersionEndExcluding:   "1.0.0",
			CriteriaDict:          knowledge_db.CriteriaDict{Part: "a", Vendor: vendor, Product: product, TargetSw: "node.js"},
		}}}},
	}
}

// nvdFindings analyses one npm package at 0.7.0 and returns the vulnerability ids found for it.
func nvdFindings(t *testing.T, pkg string, advisories productAdvisories) []string {
	t.Helper()
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{pkg: {"0.7.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	out, err := vulnerabilities.StartWithAdvisories("", sbom, "JS", time.Now(), nil, nil, advisories)
	require.NoError(t, err)
	ids := []string{}
	for _, v := range out.WorkSpaces["."].Vulnerabilities {
		require.Equal(t, pkg, v.AffectedDependency)
		ids = append(ids, v.VulnerabilityId)
	}
	return ids
}

func vendorClash() productAdvisories {
	return productAdvisories{"passport": {nodeCVE("CVE-2023-29019", "fastify", "passport",
		"https://github.com/fastify/fastify-passport/security/advisories/GHSA-4m3m-ppvx-xgw9")}}
}

func TestNodeCPEOfAnotherVendorsProjectDoesNotMatchTheUnscopedPackage(t *testing.T) {
	require.Empty(t, nvdFindings(t, "passport", vendorClash()))
}

func TestScopedPackageMatchesACPEWhoseVendorIsItsScope(t *testing.T) {
	require.Equal(t, []string{"CVE-2023-29019"}, nvdFindings(t, "@fastify/passport", vendorClash()))
}

func TestScopedPackageDoesNotMatchACPEOfAnotherVendor(t *testing.T) {
	advisories := productAdvisories{"passport": {nodeCVE("CVE-2024-0001", "jaredhanson", "passport")}}

	require.Empty(t, nvdFindings(t, "@fastify/passport", advisories))
}

func TestNodeCPEWhoseVendorIsTheProjectNameMatches(t *testing.T) {
	advisories := productAdvisories{"nanoid": {nodeCVE("CVE-2024-0002", "nanoid_project", "nanoid")}}

	require.Equal(t, []string{"CVE-2024-0002"}, nvdFindings(t, "nanoid", advisories))
}

func TestNodeCPEWhoseVendorOwnsThePackageRepositoryMatches(t *testing.T) {
	advisories := productAdvisories{"undici": {nodeCVE("CVE-2024-0003", "nodejs", "undici",
		"https://github.com/nodejs/undici/security/advisories/GHSA-qrxm-fqhp-jwvm")}}

	require.Equal(t, []string{"CVE-2024-0003"}, nvdFindings(t, "undici", advisories))
}

func TestNodeCPEOfAMaintainerWithNoConflictingRepositoryMatches(t *testing.T) {
	advisories := productAdvisories{"extract-zip": {nodeCVE("CVE-2024-0004", "max-mapper", "extract-zip",
		"https://github.com/someone/extract-zip-security-research/security/advisories/GHSA-x7jf-2287-qcpf")}}

	require.Equal(t, []string{"CVE-2024-0004"}, nvdFindings(t, "extract-zip", advisories))
}
