package nvd

import (
	"context"
	"encoding/json"
	"log"

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

	// Build the JSONB containment value safely using JSON marshaling
	containmentValue, err := json.Marshal([]map[string]map[string]string{{"criteriaDict": {"product": depName}}})
	if err != nil {
		log.Printf("Error marshaling NVD containment value: %v", err)
		return vulnerabilities, err
	}

	rows, err := knowledge.QueryContext(ctx, `
	SELECT DISTINCT id, nvd_id, "sourceIdentifier", published, "lastModified", "vulnStatus", descriptions, metrics, weaknesses, configurations, "affectedFlattened", affected, "references", vlai_score, vlai_confidence
	FROM nvd
	WHERE
	("affectedFlattened" @> ?::jsonb)
	AND ("vulnStatus" = 'Analyzed' OR "vulnStatus" = 'Modified');
	`, string(containmentValue))
	if err != nil {
		log.Printf("Error querying NVD table: %v", err)
		return vulnerabilities, err
	}

	err = knowledge.ScanRows(ctx, rows, &vulnerabilities)
	if err != nil {
		log.Printf("Error scanning NVD rows: %v", err)
		return vulnerabilities, err
	}

	return vulnerabilities, nil
}
