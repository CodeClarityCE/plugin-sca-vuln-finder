package sourcesync

import (
	"context"
	"log"
	"time"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// Snapshot records every knowledge source's sync state, or marks all sources unknown when it cannot be read.
func Snapshot(ctx context.Context, db *bun.DB, now time.Time, knowledgeAsOf *time.Time) knowledge.KnowledgeSnapshot {
	if db == nil {
		return knowledge.UnknownSnapshot(now, knowledgeAsOf)
	}
	rows := []knowledge.SourceSync{}
	// last_error is left out so upstream error text never reaches analysis results.
	err := db.NewSelect().Model(&rows).
		Column("source", "watermark", "last_outcome", "row_count", "validation_error").
		Scan(ctx)
	if err != nil {
		log.Printf("Failed to read knowledge source sync state: %v", err)
		return knowledge.UnknownSnapshot(now, knowledgeAsOf)
	}
	return knowledge.TakeSnapshot(rows, now, knowledgeAsOf)
}
