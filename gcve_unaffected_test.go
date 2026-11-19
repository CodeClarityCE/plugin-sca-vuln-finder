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

// leftPadGCVE serves one CVE record for the npm package left-pad from GCVE and nothing from the other sources.
type leftPadGCVE struct{ versions []knowledge_db.GCVEVersion }

func (leftPadGCVE) OSV(context.Context, string) ([]knowledge_db.OSVItem, error) { return nil, nil }
func (leftPadGCVE) NVD(context.Context, string) ([]knowledge_db.NVDItem, error) { return nil, nil }
func (g leftPadGCVE) GCVE(_ context.Context, name string) ([]knowledge_db.GCVEItem, error) {
	if name != "left-pad" {
		return nil, nil
	}
	return []knowledge_db.GCVEItem{{
		CVEId:         "CVE-2026-4242",
		DatePublished: "2026-01-01T00:00:00Z",
		Affected: []knowledge_db.GCVEAffected{{
			Vendor:        "left-pad_project",
			Product:       "left-pad",
			DefaultStatus: "unaffected",
			Versions:      g.versions,
		}},
		References: []knowledge_db.GCVEReference{{URL: "https://www.npmjs.com/package/left-pad"}},
	}}, nil
}

func affected(from, lessThan string) knowledge_db.GCVEVersion {
	return knowledge_db.GCVEVersion{Status: "affected", Version: from, LessThan: lessThan, VersionType: "semver"}
}

func unaffected(version string) knowledge_db.GCVEVersion {
	return knowledge_db.GCVEVersion{Status: "unaffected", Version: version, VersionType: "semver"}
}

// gcveReports says whether GCVE reports the record for left-pad at version.
func gcveReports(t *testing.T, version string, versions ...knowledge_db.GCVEVersion) bool {
	t.Helper()
	sbom := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{"left-pad": {version: {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
	out, err := vulnerabilities.StartWithAdvisories("", sbom, "JS", time.Now(), nil, nil, leftPadGCVE{versions})
	require.NoError(t, err)
	for _, vuln := range out.WorkSpaces["."].Vulnerabilities {
		if vuln.VulnerabilityId == "CVE-2026-4242" {
			return true
		}
	}
	return false
}

// The shape a CNA uses for a fix backported to an older release line.
var backportRecord = []knowledge_db.GCVEVersion{
	affected("0", "5.1.16"), unaffected("5.1.16"),
	affected("0", "3.3.16"), unaffected("3.3.16"),
}

func TestACNABackportFixListedAsUnaffectedIsNotReported(t *testing.T) {
	require.False(t, gcveReports(t, "3.3.16", backportRecord...))
	require.False(t, gcveReports(t, "3.3.18", backportRecord...))
	require.False(t, gcveReports(t, "3.9.0", backportRecord...))
}

func TestAVersionBeforeTheBackportFixIsStillReported(t *testing.T) {
	require.True(t, gcveReports(t, "3.3.15", backportRecord...))
	require.True(t, gcveReports(t, "2.1.0", backportRecord...))
}

func TestAReleaseLineWithoutABackportFixIsStillReported(t *testing.T) {
	require.True(t, gcveReports(t, "4.0.0", backportRecord...))
	require.True(t, gcveReports(t, "5.1.15", backportRecord...))
	require.False(t, gcveReports(t, "5.1.16", backportRecord...))
}

func TestAnUnaffectedRangeExcludesTheVersionsInsideIt(t *testing.T) {
	versions := []knowledge_db.GCVEVersion{
		affected("0", "2.0.0"),
		{Status: "unaffected", Version: "1.4.2", LessThan: "1.5.0", VersionType: "semver"},
	}
	require.True(t, gcveReports(t, "1.4.1", versions...))
	require.False(t, gcveReports(t, "1.4.7", versions...))
	require.True(t, gcveReports(t, "1.5.0", versions...))
}

func TestAnUnaffectedWildcardRangeExcludesItsBranch(t *testing.T) {
	versions := []knowledge_db.GCVEVersion{
		affected("0", "2.0.0"),
		{Status: "unaffected", Version: "1.4.2", LessThanOrEqual: "1.4.*", VersionType: "semver"},
	}
	require.True(t, gcveReports(t, "1.4.1", versions...))
	require.False(t, gcveReports(t, "1.4.9", versions...))
	require.True(t, gcveReports(t, "1.5.0", versions...))
}

func TestABackportFixDoesNotHideALaterAffectedRangeOnTheSameLine(t *testing.T) {
	versions := []knowledge_db.GCVEVersion{
		affected("0", "2.0.0"), unaffected("1.0.5"),
		affected("1.2.0", "1.2.3"),
	}
	require.False(t, gcveReports(t, "1.1.0", versions...))
	require.True(t, gcveReports(t, "1.2.1", versions...))
}

func TestABackportFixOnAZeroMajorLineCoversOnlyThatMinor(t *testing.T) {
	versions := []knowledge_db.GCVEVersion{affected("0", "1.0.0"), unaffected("0.9.4")}
	require.True(t, gcveReports(t, "0.9.3", versions...))
	require.False(t, gcveReports(t, "0.9.7", versions...))
	require.True(t, gcveReports(t, "0.10.0", versions...))
}

func TestAnUnaffectedExactVersionIsNotReported(t *testing.T) {
	versions := []knowledge_db.GCVEVersion{
		affected("1.0.0", ""),
		{Status: "affected", Version: "1.0.0", LessThanOrEqual: "1.9.9", VersionType: "semver"},
		unaffected("1.9.9"),
	}
	require.True(t, gcveReports(t, "1.9.8", versions...))
	require.False(t, gcveReports(t, "1.9.9", versions...))
}
