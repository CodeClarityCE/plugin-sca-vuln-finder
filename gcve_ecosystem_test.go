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
	"github.com/stretchr/testify/require"
)

// gcveAdvisories serves one GCVE record for every package it names and nothing from the other sources.
type gcveAdvisories struct{ record knowledge_db.GCVEItem }

func (gcveAdvisories) OSVByID(context.Context, []string) ([]knowledge_db.OSVItem, error) {
	return nil, nil
}
func (gcveAdvisories) NVDByID(context.Context, []string) ([]knowledge_db.NVDItem, error) {
	return nil, nil
}
func (gcveAdvisories) GCVEByID(context.Context, []string) ([]knowledge_db.GCVEItem, error) {
	return nil, nil
}

func (gcveAdvisories) OSV(context.Context, string) ([]knowledge_db.OSVItem, error) { return nil, nil }
func (gcveAdvisories) NVD(context.Context, string) ([]knowledge_db.NVDItem, error) { return nil, nil }
func (g gcveAdvisories) GCVE(_ context.Context, product string) ([]knowledge_db.GCVEItem, error) {
	for _, a := range g.record.Affected {
		if a.Product == product {
			return []knowledge_db.GCVEItem{g.record}, nil
		}
	}
	return nil, nil
}

// gcveRecord affects every version of product below 2.0.0.
func gcveRecord(vendor, product string, references ...string) knowledge_db.GCVEItem {
	refs := make([]knowledge_db.GCVEReference, 0, len(references))
	for _, url := range references {
		refs = append(refs, knowledge_db.GCVEReference{URL: url})
	}
	return knowledge_db.GCVEItem{
		CVEId:         "CVE-2024-0001",
		State:         "PUBLISHED",
		DatePublished: "2024-01-01T00:00:00Z",
		Affected: []knowledge_db.GCVEAffected{{
			Vendor:   vendor,
			Product:  product,
			Versions: []knowledge_db.GCVEVersion{{Version: "0", LessThan: "2.0.0", Status: "affected"}},
		}},
		References: refs,
	}
}

func analyzeWithGCVE(t *testing.T, pkg string, record knowledge_db.GCVEItem) []vulnerabilityFinder.Vulnerability {
	t.Helper()
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{pkg: {"1.0.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	out, err := vulnerabilities.StartWithAdvisories("", sbom, "JS", time.Now(), nil, nil, gcveAdvisories{record})
	require.NoError(t, err)
	return out.WorkSpaces["."].Vulnerabilities
}

func TestAGCVERecordForAWordPressPluginDoesNotMatchTheNpmPackageOfTheSameName(t *testing.T) {
	record := gcveRecord("Clone Plugins", "clone",
		"https://patchstack.com/database/vulnerability/clone/wordpress-clone-plugin-1-0-0-csrf",
		"https://wordpress.org/plugins/clone/")

	require.Empty(t, analyzeWithGCVE(t, "clone", record))
}

func TestAGCVERecordForAnotherProductWithoutAnyReferenceDoesNotMatchAnNpmPackage(t *testing.T) {
	record := gcveRecord("i2A", "negotiator")

	require.Empty(t, analyzeWithGCVE(t, "negotiator", record))
}

func TestAGCVERecordWhoseVendorOwnsThePackageRepositoryMatches(t *testing.T) {
	record := gcveRecord("nodemailer", "nodemailer",
		"https://github.com/nodemailer/nodemailer/security/advisories/GHSA-aaaa-bbbb-cccc")

	vulns := analyzeWithGCVE(t, "nodemailer", record)

	require.Len(t, vulns, 1)
	require.Equal(t, "CVE-2024-0001", vulns[0].VulnerabilityId)
}

func TestAGCVERecordReferencingTheNpmPackagePageMatches(t *testing.T) {
	record := gcveRecord("Gary Court", "uri-js", "https://www.npmjs.com/package/uri-js")

	require.Len(t, analyzeWithGCVE(t, "uri-js", record), 1)
}

func TestAGCVERecordForAScopedPackageWhoseVendorIsTheScopeMatches(t *testing.T) {
	record := gcveRecord("fastify", "@fastify/proxy-addr")

	require.Len(t, analyzeWithGCVE(t, "@fastify/proxy-addr", record), 1)
}
