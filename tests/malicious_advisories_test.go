package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/conflictResolver"
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	packageRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/osv"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

const maliciousAdvisoriesSchema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- Empty NVD and GCVE tables: the matcher reads every source, and a missing table fails the run.
CREATE TABLE nvd (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	nvd_id varchar, "sourceIdentifier" varchar, published varchar, "lastModified" varchar, "vulnStatus" varchar,
	descriptions jsonb, metrics jsonb, weaknesses jsonb, configurations jsonb, "affectedFlattened" jsonb, affected jsonb,
	"references" jsonb, retired_reason varchar, retired_at timestamptz, vlai_score varchar, vlai_confidence double precision
);
CREATE TABLE gcve (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	gcve_id varchar, cve_id varchar, data_version varchar, state varchar, date_published varchar, date_updated varchar,
	assigner_org_id varchar, descriptions jsonb, affected jsonb, affected_flattened jsonb, metrics jsonb, problem_types jsonb,
	"references" jsonb, adp_enrichments jsonb, cwes jsonb, vlai_score varchar, vlai_confidence double precision,
	retired_reason varchar, retired_at timestamptz
);
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

// maliciousAdvisoriesDB returns a throwaway knowledge database holding the rows above.
func maliciousAdvisoriesDB(t *testing.T) *bun.DB {
	t.Helper()
	db := testdeps.Postgres(t)
	_, err := db.ExecContext(context.Background(), maliciousAdvisoriesSchema)
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

	vulnerabilities, advisories, err := vm.GetWorkspaceFindings(context.Background(), dependencies, db)
	require.NoError(t, err)

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

	_, listed, _ := vm.GetWorkspaceFindings(context.Background(), map[string]map[string]sbomTypes.Versions{
		"vl-ui-contact-card": {"10.1.1": {Direct: true}},
	}, db)
	_, unlisted, _ := vm.GetWorkspaceFindings(context.Background(), map[string]map[string]sbomTypes.Versions{
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
		_, advisories, _ := vm.GetWorkspaceFindings(context.Background(), map[string]map[string]sbomTypes.Versions{
			"ng2-file-upload": {version: {Direct: true}},
		}, db)
		return len(advisories) == 1
	}

	assert.True(t, flagged("8.0.3"))
	assert.True(t, flagged("7.0.3"))
	assert.False(t, flagged("8.0.4"))
	assert.False(t, flagged("7.0.4"))
}
