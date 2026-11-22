package sourcesync

import (
	"context"
	"testing"
	"time"

	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// sourceSyncDDL matches the knowledge_source_sync API migrations.
const sourceSyncDDL = `
CREATE TABLE knowledge_source_sync (
	source character varying NOT NULL PRIMARY KEY,
	watermark timestamptz,
	last_run_started_at timestamptz,
	last_run_finished_at timestamptz,
	last_outcome character varying CHECK (last_outcome IN ('success', 'failure')),
	last_error text,
	row_count bigint NOT NULL DEFAULT 0,
	bulk_completed_at timestamptz,
	validated_row_count bigint,
	validated_malicious_count bigint,
	validated_at timestamptz,
	validation_error text
)`

// syncTestDB returns a throwaway database, with the knowledge_source_sync table when asked.
func syncTestDB(t *testing.T, withTable bool) *bun.DB {
	t.Helper()
	db := testdeps.Postgres(t)
	if withTable {
		if _, err := db.ExecContext(context.Background(), sourceSyncDDL); err != nil {
			t.Fatalf("create knowledge_source_sync: %v", err)
		}
	}
	return db
}

func TestSnapshotReadsEachSourcesSyncState(t *testing.T) {
	db := syncTestDB(t, true)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	_, err := db.ExecContext(context.Background(), `INSERT INTO knowledge_source_sync (source, watermark, last_outcome, row_count, last_error) VALUES
		('osv', '2026-11-09T06:00:00Z', 'success', 238664, NULL),
		('nvd', '2026-11-01T00:00:00Z', 'failure', 159450, 'upstream timed out')`)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := Snapshot(context.Background(), db, now, nil)

	got := map[string]knowledge.SourceSnapshot{}
	for _, source := range snapshot.Sources {
		got[source.Source] = source
	}
	if osv := got["osv"]; osv.Status != knowledge.SourceHealthy || osv.RowCount != 238664 || !osv.Comparable {
		t.Errorf("osv = %+v, want healthy with 238664 rows", osv)
	}
	if nvd := got["nvd"]; nvd.Status != knowledge.SourceFailed || nvd.Comparable || nvd.RowCount != 159450 {
		t.Errorf("nvd = %+v, want failed and not comparable", nvd)
	}
}

func TestSnapshotIsUnknownWhenSyncStateCannotBeRead(t *testing.T) {
	db := syncTestDB(t, false)

	snapshot := Snapshot(context.Background(), db, time.Now(), nil)

	for _, source := range snapshot.Sources {
		if source.Status != knowledge.SourceUnknown || source.Comparable {
			t.Errorf("%s = %+v, want unknown", source.Source, source)
		}
	}
	if len(snapshot.Sources) != len(knowledge.AllSources) {
		t.Errorf("got %d sources, want %d", len(snapshot.Sources), len(knowledge.AllSources))
	}
}

func TestSnapshotWithoutAKnowledgeDatabaseIsUnknown(t *testing.T) {
	snapshot := Snapshot(context.Background(), nil, time.Now(), nil)

	if len(snapshot.Sources) == 0 || snapshot.Sources[0].Status != knowledge.SourceUnknown {
		t.Errorf("snapshot = %+v, want every source unknown", snapshot)
	}
}
