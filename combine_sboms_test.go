package main

import (
	"errors"
	"testing"
	"time"

	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
)

func vulnOutput(status codeclarity.AnalysisStatus, workspace string) vulnerabilityFinder.Output {
	output := vulnerabilityFinder.Output{WorkSpaces: map[string]vulnerabilityFinder.Workspace{workspace: {}}}
	output.AnalysisInfo.Status = status
	return output
}

func TestCombineVulnOutputs(t *testing.T) {
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}, {uuid.New(), "PHP", "php-sbom"}}
	ok := func(k sbomKey) (vulnerabilityFinder.Output, error) {
		return vulnOutput(codeclarity.SUCCESS, k.language), nil
	}
	cases := []struct {
		name    string
		php     func(sbomKey) (vulnerabilityFinder.Output, error)
		want    codeclarity.AnalysisStatus
		wantLen int
	}{
		{"every SBOM succeeds", ok, codeclarity.SUCCESS, 2},
		{"an SBOM cannot be loaded", func(sbomKey) (vulnerabilityFinder.Output, error) {
			return vulnerabilityFinder.Output{}, errors.New("load failed")
		}, codeclarity.FAILURE, 0},
		{"an SBOM cannot be processed", func(sbomKey) (vulnerabilityFinder.Output, error) {
			return vulnOutput(codeclarity.FAILURE, "php"), nil
		}, codeclarity.FAILURE, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := combineVulnOutputs(keys, func(k sbomKey) (vulnerabilityFinder.Output, error) {
				if k.language == "PHP" {
					return tc.php(k)
				}
				return ok(k)
			}, time.Now())
			if out.AnalysisInfo.Status != tc.want || len(out.WorkSpaces) != tc.wantLen {
				t.Fatalf("status = %s with %d workspaces", out.AnalysisInfo.Status, len(out.WorkSpaces))
			}
		})
	}
}

func TestCombineVulnOutputsSaysWhichSbomFailed(t *testing.T) {
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}, {uuid.New(), "PHP", "php-sbom"}}
	cases := []struct {
		name    string
		analyze func(sbomKey) (vulnerabilityFinder.Output, error)
		want    string
	}{
		{"cannot be loaded", func(k sbomKey) (vulnerabilityFinder.Output, error) {
			if k.language == "PHP" {
				return vulnerabilityFinder.Output{}, errors.New("pq: secret detail at /srv/x")
			}
			return vulnOutput(codeclarity.SUCCESS, k.language), nil
		}, "the PHP dependency list could not be read"},
		{"cannot be processed", func(k sbomKey) (vulnerabilityFinder.Output, error) {
			return vulnOutput(codeclarity.FAILURE, k.language), nil
		}, "the JavaScript dependencies could not be checked for vulnerabilities"},
		{"every SBOM succeeds", func(k sbomKey) (vulnerabilityFinder.Output, error) {
			return vulnOutput(codeclarity.SUCCESS, k.language), nil
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, reason := combineVulnOutputs(keys, tc.analyze, time.Now())
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
		})
	}
}

func TestCombineVulnOutputsKeepsMaliciousAdvisoriesFromEverySbom(t *testing.T) {
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}, {uuid.New(), "PHP", "php-sbom"}}

	out, _ := combineVulnOutputs(keys, func(k sbomKey) (vulnerabilityFinder.Output, error) {
		output := vulnerabilityFinder.Output{WorkSpaces: map[string]vulnerabilityFinder.Workspace{
			".": {MaliciousPackageAdvisories: []vulnerabilityFinder.MaliciousPackageAdvisory{{AdvisoryId: "MAL-" + k.language}}},
		}}
		output.AnalysisInfo.Status = codeclarity.SUCCESS
		return output, nil
	}, time.Now())

	got := out.WorkSpaces["."].MaliciousPackageAdvisories
	if len(got) != 2 || got[0].AdvisoryId != "MAL-JS" || got[1].AdvisoryId != "MAL-PHP" {
		t.Fatalf("advisories = %+v, want MAL-JS and MAL-PHP", got)
	}
}
