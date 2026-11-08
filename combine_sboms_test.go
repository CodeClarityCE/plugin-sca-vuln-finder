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
			out := combineVulnOutputs(keys, func(k sbomKey) (vulnerabilityFinder.Output, error) {
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
