package nvd

import (
	"context"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func GetVulnsByDepName(depName string, knowledge *bun.DB) ([]knowledge_db.NVDItem, error) {
	vulnerabilities := []knowledge_db.NVDItem{}

	ctx := context.Background()

	// TODO avoid SQL injection
	rows, err := knowledge.QueryContext(ctx, `
		WITH preselect AS(SELECT *, jsonb_path_query("affectedFlattened", '$[*].criteriaDict.product ?(@=="`+depName+`")')
		FROM nvd)

		SELECT DISTINCT id, nvd_id, "sourceIdentifier", published, "lastModified", "vulnStatus", descriptions, metrics, weaknesses, configurations, "affectedFlattened", affected, "references"
		FROM preselect
		WHERE "vulnStatus" = 'Analyzed' OR "vulnStatus" = 'Modified'
	`)
	if err != nil {
		panic(err)
	}

	err = knowledge.ScanRows(ctx, rows, &vulnerabilities)
	if err != nil {
		panic(err)
	}

	return vulnerabilities, nil
}