package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// knowledgeSchema has the knowledge tables an analysis reads.
const knowledgeSchema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
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
`

// knowledgeDB returns a throwaway knowledge database with the schema above and the given rows.
func knowledgeDB(t *testing.T, rows string) *bun.DB {
	t.Helper()
	db := testdeps.Postgres(t)
	ctx := context.Background()
	_, err := db.ExecContext(ctx, knowledgeSchema)
	require.NoError(t, err)
	for _, model := range []any{(*knowledge_db.EPSS)(nil), (*knowledge_db.FriendsOfPHPAdvisory)(nil)} {
		_, err = db.NewCreateTable().Model(model).Exec(ctx)
		require.NoError(t, err)
	}
	if rows != "" {
		_, err = db.ExecContext(ctx, rows)
		require.NoError(t, err)
	}
	return db
}

func TestNPMProjectReportsAnAdvisoryForItsVersion(t *testing.T) {
	db := knowledgeDB(t, `INSERT INTO osv (osv_id, summary, aliases, affected) VALUES
		('GHSA-test-ansi-regex', 'ReDoS in ansi-regex', '[]',
		 '[{"package":{"ecosystem":"npm","name":"ansi-regex","purl":"pkg:npm/ansi-regex"},"ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"3.0.1"}]}]}]')`)
	sbom, err := getSBOM("../testdata/sbom/npm")
	require.NoError(t, err)

	out, err := vulnerabilities.Start("", sbom, "JS", time.Now(), db, nil)

	require.NoError(t, err)
	require.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status, "errors: %+v", out.AnalysisInfo.Errors)
	found := []string{}
	for _, vuln := range out.WorkSpaces["."].Vulnerabilities {
		found = append(found, vuln.VulnerabilityId+" "+vuln.AffectedDependency+"@"+vuln.AffectedVersion)
	}
	assert.Equal(t, []string{"GHSA-test-ansi-regex ansi-regex@2.1.1"}, found)
}

func TestComposerProjectWithoutAdvisoriesHasNoFindings(t *testing.T) {
	db := knowledgeDB(t, "")
	sbom, err := getSBOM("../testdata/sbom/composer")
	require.NoError(t, err)

	out, err := vulnerabilities.Start("", sbom, "PHP", time.Now(), db, nil)

	require.NoError(t, err)
	require.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status, "errors: %+v", out.AnalysisInfo.Errors)
	require.Contains(t, out.WorkSpaces, ".")
	assert.Empty(t, out.WorkSpaces["."].Vulnerabilities)
}
