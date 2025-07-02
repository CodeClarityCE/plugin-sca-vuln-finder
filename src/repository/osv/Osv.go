package osv

import (
	"context"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// GetAllOSVReportsForPurl retrieves all OSV reports for a given package URL (purl).
// It first checks if the reports are already cached, and if not, it queries the database to fetch the reports.
// The function returns a slice of OSVItem, which represents the OSV reports, and an error if any.
func GetAllOSVReportsForPurl(purl string, knowledge *bun.DB) ([]knowledge_db.OSVItem, error) {
	matches := []knowledge_db.OSVItem{}

	ctx := context.Background()

	// TODO avoid SQL injection
	// ("@purl IN osv_report.affected[*].package.purl")
	rows, err := knowledge.QueryContext(ctx, `
		SELECT DISTINCT "id", "osv_id", "schema_version", "modified", "published", "withdrawn", "aliases", "related", "summary", "details", "severity", "affected", "references", "credits", "database_specific", "cwes", "cve", vlai_score, vlai_confidence
		FROM osv
		WHERE ("affected" @> '[{"package": {"purl": "`+purl+`"}}]')
	`)
	if err != nil {
		panic(err)
	}

	err = knowledge.ScanRows(ctx, rows, &matches)
	if err != nil {
		panic(err)
	}

	return matches, nil
}
