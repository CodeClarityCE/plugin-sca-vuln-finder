package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/gcve"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/nvd"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/osv"
	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
)

const recordsByIDSchema = `
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE nvd (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	nvd_id varchar, "sourceIdentifier" varchar, published varchar, "lastModified" varchar, "vulnStatus" varchar,
	descriptions jsonb, metrics jsonb, weaknesses jsonb, configurations jsonb, "affectedFlattened" jsonb, affected jsonb,
	"references" jsonb, retired_reason varchar, retired_at timestamptz, vlai_score varchar, vlai_confidence double precision
);
CREATE TABLE gcve (
	id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
	gcve_id varchar NOT NULL, cve_id varchar, data_version varchar, state varchar, date_published varchar, date_updated varchar,
	assigner_org_id varchar, descriptions jsonb, affected jsonb, affected_flattened jsonb, metrics jsonb, problem_types jsonb,
	"references" jsonb, adp_enrichments jsonb, cwes text[] DEFAULT '{}', vlai_score varchar, vlai_confidence double precision,
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
	retired_at timestamptz,
	cve_aliases jsonb GENERATED ALWAYS AS (
		COALESCE(jsonb_path_query_array(aliases, '$[*] ? (@ starts with "CVE-")'), '[]'::jsonb)
	) STORED
);
INSERT INTO osv (osv_id, aliases, affected, withdrawn) VALUES
	('GHSA-aaaa-aaaa-aaaa', '["CVE-2024-0001"]', '[]', '2025-03-01T00:00:00Z'),
	('GHSA-bbbb-bbbb-bbbb', '["CVE-2024-0002"]', '[]', NULL),
	('GHSA-cccc-cccc-cccc', '[]', '[]', NULL),
	('GHSA-dddd-dddd-dddd', '["CVE-2024-0009"]', '[]', NULL);
UPDATE osv SET cve = 'CVE-2024-0003' WHERE osv_id = 'GHSA-cccc-cccc-cccc';
INSERT INTO nvd (nvd_id, "vulnStatus", affected) VALUES
	('CVE-2024-0001', 'Awaiting Analysis', '[]'), ('CVE-2024-0009', 'Analyzed', '[]');
INSERT INTO gcve (gcve_id, cve_id, state, affected, retired_reason, retired_at) VALUES
	('GCVE-1-2024-0001', NULL, 'PUBLISHED', '[{"vendor":"acme","product":"leftpad-cli"}]', NULL, NULL),
	('GCVE-0-2024-0002', 'CVE-2024-0002', 'REJECTED', '[]', 'rejected', '2025-04-02T00:00:00Z'),
	('GCVE-0-2024-0009', 'CVE-2024-0009', 'PUBLISHED', '[]', NULL, NULL);`

func recordsByIDDB(t *testing.T) *bun.DB {
	t.Helper()
	db := testdeps.Postgres(t)
	_, err := db.ExecContext(context.Background(), recordsByIDSchema)
	require.NoError(t, err)
	return db
}

func TestRecordsAreFoundByTheirOwnIDOrACVEAliasRetiredOnesToo(t *testing.T) {
	db := recordsByIDDB(t)
	ctx := context.Background()
	ids := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "GCVE-1-2024-0001"}

	osvRecords, err := osv.GetByIDsContext(ctx, ids, db)
	require.NoError(t, err)
	osvIDs := []string{}
	for _, record := range osvRecords {
		osvIDs = append(osvIDs, record.OSVId)
	}
	assert.ElementsMatch(t, []string{"GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "GHSA-cccc-cccc-cccc"}, osvIDs)

	nvdRecords, err := nvd.GetByIDsContext(ctx, ids, db)
	require.NoError(t, err)
	require.Len(t, nvdRecords, 1)
	assert.Equal(t, "Awaiting Analysis", nvdRecords[0].VulnStatus)

	gcveRecords, err := gcve.GetByIDsContext(ctx, ids, db)
	require.NoError(t, err)
	byID := map[string]string{}
	for _, record := range gcveRecords {
		byID[record.GCVEId] = record.RetiredReason
	}
	assert.Equal(t, map[string]string{"GCVE-1-2024-0001": "", "GCVE-0-2024-0002": "rejected"}, byID)
}
