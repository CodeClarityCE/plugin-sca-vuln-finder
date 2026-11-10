package main

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"

	frameworkMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/frameworks"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// nvdStatusDB creates a throwaway knowledge database holding one Laravel CVE per NVD status.
func nvdStatusDB(t *testing.T) *bun.DB {
	t.Helper()
	ctx := context.Background()
	admin := openDatabase("postgres")
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		t.Skipf("Skipping test due to database connection error: %v", err)
	}
	name := "nvd_status_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err := admin.ExecContext(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)

	db := bun.NewDB(openDatabase(name), pgdialect.New())
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.ExecContext(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
	_, err = db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`)
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
