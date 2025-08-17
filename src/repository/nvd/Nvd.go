package nvd

import (
	"context"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

func GetVulnsByDepName(depName string, knowledge *bun.DB) ([]knowledge_db.NVDItem, error) {
	vulnerabilities := []knowledge_db.NVDItem{}

	// Handle nil knowledge database gracefully
	if knowledge == nil {
		return vulnerabilities, nil
	}

	ctx := context.Background()

	// TODO avoid SQL injection
	rows, err := knowledge.QueryContext(ctx, `
	SELECT DISTINCT id, nvd_id, "sourceIdentifier", published, "lastModified", "vulnStatus", descriptions, metrics, weaknesses, configurations, "affectedFlattened", affected, "references", vlai_score, vlai_confidence
	FROM nvd
	WHERE 
	("affectedFlattened" @> '[{"criteriaDict": {"product": "`+depName+`"}}]')
	AND ("vulnStatus" = 'Analyzed' OR "vulnStatus" = 'Modified');
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
