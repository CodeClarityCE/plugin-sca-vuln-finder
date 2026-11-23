package main

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	frameworkMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/frameworks"
	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// nvdStatusDB creates a throwaway knowledge database holding one Laravel CVE per NVD status.
func nvdStatusDB(t *testing.T) *bun.DB {
	t.Helper()
	ctx := context.Background()
	db := testdeps.Postgres(t)
	_, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`)
	require.NoError(t, err)
	_, err = db.NewCreateTable().Model((*knowledge_db.NVDItem)(nil)).Exec(ctx)
	require.NoError(t, err)

	affected := `[{"sources":[{"criteriaDict":{"vendor":"laravel","product":"laravel"}}]}]`
	for id, status := range map[string]string{
		"CVE-ANALYZED": "Analyzed",
		"CVE-MODIFIED": "Modified",
		"CVE-DEFERRED": "Deferred",
		"CVE-AWAITING": "Awaiting Analysis",
	} {
		_, err = db.ExecContext(ctx,
			`INSERT INTO nvd (nvd_id, "vulnStatus", affected) VALUES (?, ?, ?::jsonb)`, id, status, affected)
		require.NoError(t, err)
	}
	return db
}

func TestPHPFrameworkMatchingUsesOnlyAnalyzedOrModifiedNVDRecords(t *testing.T) {
	db := nvdStatusDB(t)

	matches, err := frameworkMatcher.PHPFrameworkVulnerabilityMatcher{}.
		MatchFrameworkVulnerabilities("Laravel", "unknown", db)

	require.NoError(t, err)
	found := map[string]bool{}
	for _, match := range matches {
		if match.Source == "NVD Database" {
			found[match.VulnerabilityID] = true
		}
	}
	got := []string{}
	for id := range found {
		got = append(got, id)
	}
	sort.Strings(got)
	assert.Equal(t, []string{"CVE-ANALYZED", "CVE-MODIFIED"}, got)
}
