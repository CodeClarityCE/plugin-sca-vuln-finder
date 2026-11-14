package sourcesync

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
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

func openDB(dsn string, params map[string]any) *bun.DB {
	options := []pgdriver.Option{pgdriver.WithDSN(dsn)}
	if params != nil {
		options = append(options, pgdriver.WithConnParams(params))
	}
	return bun.NewDB(sql.OpenDB(pgdriver.NewConnector(options...)), pgdialect.New())
}

// syncTestDB opens a fresh schema in the throwaway database named by KNOWLEDGE_SYNC_TEST_DSN.
func syncTestDB(t *testing.T, withTable bool) *bun.DB {
	t.Helper()
	dsn := os.Getenv("KNOWLEDGE_SYNC_TEST_DSN")
	if dsn == "" {
		t.Skip("KNOWLEDGE_SYNC_TEST_DSN is not set")
	}
	ctx := context.Background()
	schema := "snapshot_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	admin := openDB(dsn, nil)
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	db := openDB(dsn, map[string]any{"search_path": schema})
	t.Cleanup(func() {
		db.Close()
		cleaner := openDB(dsn, nil)
		defer cleaner.Close()
		_, _ = cleaner.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE")
	})
	if withTable {
		if _, err := db.ExecContext(ctx, sourceSyncDDL); err != nil {
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
