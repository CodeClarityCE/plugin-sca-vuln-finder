package nvd

import (
	"context"
	"encoding/json"
	"log"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// MatchableStatus selects the NVD CVEs vuln-finder matches: Analyzed or Modified, never Deferred or Rejected.
const MatchableStatus = `("vulnStatus" = 'Analyzed' OR "vulnStatus" = 'Modified')`

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
	SELECT DISTINCT id, nvd_id, "sourceIdentifier", published, "lastModified", "vulnStatus", descriptions, metrics, weaknesses, configurations, "affectedFlattened", affected, "references", retired_reason, retired_at, vlai_score, vlai_confidence
	FROM nvd
	WHERE
	("affectedFlattened" @> ?::jsonb)
	AND `+MatchableStatus+`;
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
