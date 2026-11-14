package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/conflictResolver"
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	packageRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/osv"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

const maliciousAdvisoriesSchema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE osv (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	osv_id varchar NOT NULL UNIQUE,
	schema_version varchar, vlai_score varchar, vlai_confidence double precision,
	modified timestamptz, published timestamptz, withdrawn timestamptz,
	aliases jsonb, related jsonb, summary varchar, details varchar, severity jsonb,
	affected jsonb, "references" jsonb, credits jsonb, database_specific jsonb,
	cwes jsonb, cve varchar,
	kind varchar NOT NULL DEFAULT 'vulnerability',
	retired_reason varchar,
	retired_at timestamptz
);
INSERT INTO osv (osv_id, kind, summary, affected, aliases) VALUES
	('MAL-2024-1', 'malicious', 'Malicious code in evil-pkg',
	 '[{"package":{"ecosystem":"npm","name":"evil-pkg","purl":"pkg:npm/evil-pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.1"}]}]}]', '[]'),
	('GHSA-aaaa-bbbb-cccc', 'vulnerability', 'Prototype pollution in evil-pkg',
	 '[{"package":{"ecosystem":"npm","name":"evil-pkg","purl":"pkg:npm/evil-pkg"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.1"}]}]}]', '[]'),
	('MAL-2026-995', 'malicious', 'Malicious code in vl-ui-contact-card (npm)',
	 '[{"package":{"ecosystem":"npm","name":"vl-ui-contact-card","purl":"pkg:npm/vl-ui-contact-card"},"ranges":null,"severity":null,"versions":["10.1.1"]}]', '[]'),
	('MAL-2025-47196', 'malicious', 'Malicious code in ng2-file-upload (npm)',
	 '[{"package":{"ecosystem":"npm","name":"ng2-file-upload","purl":"pkg:npm/ng2-file-upload"},"ranges":[{"type":"SEMVER","events":[{"introduced":"8.0.1","fixed":"","last_affected":"","limit":""},{"introduced":"","fixed":"","last_affected":"8.0.3","limit":""},{"introduced":"7.0.2","fixed":"","last_affected":"","limit":""},{"introduced":"","fixed":"","last_affected":"7.0.3","limit":""}]}],"severity":null,"versions":null}]', '[]');
CREATE TABLE package (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	name varchar, language varchar, description varchar, homepage varchar, latest_version varchar,
	versions jsonb, time timestamptz, keywords jsonb, source jsonb, license varchar, licenses jsonb, extra jsonb
);
CREATE TABLE version (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	package_id uuid, version varchar, dependencies jsonb, dev_dependencies jsonb, extra jsonb,
	created_at timestamptz, updated_at timestamptz
);
INSERT INTO package (name) VALUES ('ng2-file-upload');
INSERT INTO version (package_id, version)
	SELECT id, v FROM package, unnest(ARRAY['7.0.1','7.0.2','7.0.3','7.0.4','8.0.1','8.0.2','8.0.3','8.0.4']) v;`

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func openDatabase(name string) *sql.DB {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		url.QueryEscape(envOr("PG_DB_USER", "postgres")),
		url.QueryEscape(envOr("PG_DB_PASSWORD", "!ChangeMe!")),
		envOr("PG_DB_HOST", "127.0.0.1"),
		envOr("PG_DB_PORT", "5432"),
		name)
	return sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
}

// maliciousAdvisoriesDB creates a throwaway knowledge database and drops it after the test.
func maliciousAdvisoriesDB(t *testing.T) *bun.DB {
	t.Helper()
	ctx := context.Background()
	admin := openDatabase("postgres")
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		t.Skipf("Skipping test due to database connection error: %v", err)
	}
	name := "malicious_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	_, err := admin.ExecContext(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)

	db := bun.NewDB(openDatabase(name), pgdialect.New())
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.ExecContext(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close()
	})
	_, err = db.ExecContext(ctx, maliciousAdvisoriesSchema)
	require.NoError(t, err)
	return db
}

func TestOSVReportsCarryTheirAdvisoryKind(t *testing.T) {
	db := maliciousAdvisoriesDB(t)

	reports, err := osv.GetAllOSVReportsForPurl("pkg:npm/evil-pkg", db)

	require.NoError(t, err)
	kinds := map[string]string{}
	for _, report := range reports {
		kinds[report.OSVId] = report.Kind
	}
	assert.Equal(t, map[string]string{
		"MAL-2024-1":          knowledge_db.AdvisoryKindMalicious,
		"GHSA-aaaa-bbbb-cccc": knowledge_db.AdvisoryKindVulnerability,
	}, kinds)
}

func TestWithoutMaliciousDropsMaliciousAdvisories(t *testing.T) {
	kept := osv.WithoutMalicious([]knowledge_db.OSVItem{
		{OSVId: "MAL-2024-1", Kind: knowledge_db.AdvisoryKindMalicious},
		{OSVId: "GHSA-aaaa-bbbb-cccc", Kind: knowledge_db.AdvisoryKindVulnerability},
		{OSVId: "FRIENDSOFPHP-1"},
	})

	assert.Equal(t, []string{"GHSA-aaaa-bbbb-cccc", "FRIENDSOFPHP-1"}, ids(kept))
}

func TestWorkspaceFindingsReportMaliciousAdvisoriesSeparately(t *testing.T) {
	db := maliciousAdvisoriesDB(t)
	vm := matcher.VulnerabilityMatcher{
		Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
		ConflictResolver:  conflictResolver.TrustOSVFirst,
		PackageRepository: packageRepository.PackageRepository{},
	}
	dependencies := map[string]map[string]sbomTypes.Versions{
		"evil-pkg": {"1.0.0": {Direct: true}},
	}

	vulnerabilities, advisories := vm.GetWorkspaceFindings(dependencies, db)

	require.Len(t, vulnerabilities, 1)
	assert.Equal(t, "GHSA-aaaa-bbbb-cccc", vulnerabilities[0].VulnerabilityId)
	require.Len(t, advisories, 1)
	assert.Equal(t, "MAL-2024-1", advisories[0].AdvisoryId)
	assert.Equal(t, "evil-pkg", advisories[0].AffectedDependency)
	assert.True(t, advisories[0].DirectDependency)
}

func TestWorkspaceFindingsReportMalwareListedByExactVersion(t *testing.T) {
	db := maliciousAdvisoriesDB(t)
	vm := matcher.VulnerabilityMatcher{
		Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
		ConflictResolver:  conflictResolver.TrustOSVFirst,
		PackageRepository: packageRepository.PackageRepository{},
	}

	_, listed := vm.GetWorkspaceFindings(map[string]map[string]sbomTypes.Versions{
		"vl-ui-contact-card": {"10.1.1": {Direct: true}},
	}, db)
	_, unlisted := vm.GetWorkspaceFindings(map[string]map[string]sbomTypes.Versions{
		"vl-ui-contact-card": {"10.1.2": {Direct: true}},
	}, db)

	require.Len(t, listed, 1)
	assert.Equal(t, "MAL-2026-995", listed[0].AdvisoryId)
	assert.Equal(t, "10.1.1", listed[0].AffectedVersion)
	assert.Empty(t, unlisted)
}

func TestWorkspaceFindingsReportMalwareInEveryAffectedInterval(t *testing.T) {
	db := maliciousAdvisoriesDB(t)
	vm := matcher.VulnerabilityMatcher{
		Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
		ConflictResolver:  conflictResolver.TrustOSVFirst,
		PackageRepository: packageRepository.PackageRepository{},
	}
	flagged := func(version string) bool {
		_, advisories := vm.GetWorkspaceFindings(map[string]map[string]sbomTypes.Versions{
			"ng2-file-upload": {version: {Direct: true}},
		}, db)
		return len(advisories) == 1
	}

	assert.True(t, flagged("8.0.3"))
	assert.True(t, flagged("7.0.3"))
	assert.False(t, flagged("8.0.4"))
	assert.False(t, flagged("7.0.4"))
}
