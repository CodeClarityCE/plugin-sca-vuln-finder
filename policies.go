package main

import (
	"context"
	"encoding/json"
	"strings"

	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/uptrace/bun"
)

// vulnerabilityPolicyIDs are the vulnerability policies the analysis applies, from its vuln-finder config.
func vulnerabilityPolicyIDs(analysis codeclarity.Analysis, pluginName string) []string {
	pluginConfig, ok := analysis.Config[pluginName].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := pluginConfig["vulnerabilityPolicy"].([]any)
	if !ok {
		return nil
	}
	ids := []string{}
	for _, value := range raw {
		if id, ok := value.(string); ok && strings.TrimSpace(id) != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// policyExcludedVulnerabilities reads the vulnerability IDs the analysis's policies exclude,
// from the organization's own vulnerability policies only, as the API does.
func policyExcludedVulnerabilities(ctx context.Context, db *bun.DB, analysis codeclarity.Analysis, pluginName string) (map[string]bool, error) {
	excluded := map[string]bool{}
	ids := vulnerabilityPolicyIDs(analysis, pluginName)
	if len(ids) == 0 {
		return excluded, nil
	}
	var contents []json.RawMessage
	err := db.NewSelect().
		TableExpr("policy AS p").
		ColumnExpr("p.content").
		Join(`JOIN organization_policies_policy AS op ON op."policyId" = p.id`).
		Where("p.id::text IN (?)", bun.In(ids)).
		Where("p.policy_type = ?", "VULNERABILITY_POLICY").
		Where(`op."organizationId" = ?`, analysis.OrganizationId).
		Scan(ctx, &contents)
	if err != nil {
		return excluded, err
	}
	for _, content := range contents {
		var vulns []string
		if json.Unmarshal(content, &vulns) == nil {
			for _, id := range vulns {
				excluded[id] = true
			}
		}
	}
	return excluded, nil
}
