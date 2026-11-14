package main

import (
	"strings"
	"testing"

	amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
)

func sbomStep(name string, result map[string]any) []codeclarity.Step {
	return []codeclarity.Step{{Name: name, Status: codeclarity.SUCCESS, Result: result}}
}

func TestStartAnalysisReportsWhyItFailed(t *testing.T) {
	cfg := plugin.Plugin{Name: "vuln-finder"}
	cases := []struct {
		name     string
		analysis codeclarity.Analysis
		want     string
	}{
		{
			name:     "knowledge date is not text",
			analysis: codeclarity.Analysis{Config: map[string]any{"vuln-finder": map[string]any{"knowledge_asof": 12}}},
			want:     "knowledge date",
		},
		{
			name:     "knowledge date is malformed",
			analysis: codeclarity.Analysis{Config: map[string]any{"vuln-finder": map[string]any{"knowledge_asof": "soon"}}},
			want:     "YYYY-MM-DD",
		},
		{
			name:     "SBOM result has no key",
			analysis: codeclarity.Analysis{Steps: [][]codeclarity.Step{sbomStep("js-sbom", map[string]any{"other": 1})}},
			want:     "JavaScript dependency list",
		},
		{
			name:     "SBOM key is invalid",
			analysis: codeclarity.Analysis{Steps: [][]codeclarity.Step{sbomStep("php-sbom", map[string]any{"sbomKey": "nope"})}},
			want:     "PHP dependency list",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, status, err := startAnalysis(nil, amqp.DispatcherPluginMessage{}, cfg, tc.analysis)
			if err != nil {
				t.Fatalf("a returned error loses the reason, got %v", err)
			}
			if status != codeclarity.FAILURE {
				t.Fatalf("status = %s", status)
			}
			reason, _ := result[codeclarity.StepFailureReasonKey].(string)
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("reason = %q, want it to mention %q", reason, tc.want)
			}
		})
	}
}
