package gcve

import (
	"context"
	"encoding/json"
	"log"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// GetVulnsByProduct retrieves GCVE records matching a product name.
// Uses the GIN-indexed JSONB containment query on affected_flattened.
func GetVulnsByProduct(product string, knowledge *bun.DB) ([]knowledge_db.GCVEItem, error) {
	vulnerabilities := []knowledge_db.GCVEItem{}

	if knowledge == nil {
		return vulnerabilities, nil
	}

	ctx := context.Background()

	// Build the JSONB containment value safely using JSON marshaling
	containmentValue, err := json.Marshal([]map[string]string{{"product": product}})
	if err != nil {
		log.Printf("Error marshaling GCVE containment value: %v", err)
		return vulnerabilities, err
	}

	rows, err := knowledge.QueryContext(ctx, `
	SELECT DISTINCT id, gcve_id, cve_id, data_version, state, date_published, date_updated,
	       assigner_org_id, descriptions, affected, affected_flattened, metrics, problem_types,
	       "references", adp_enrichments, cwes, vlai_score, vlai_confidence
	FROM gcve
	WHERE ("affected_flattened" @> ?::jsonb)
	AND state = 'PUBLISHED';
	`, string(containmentValue))
	if err != nil {
		log.Printf("Error querying GCVE table: %v", err)
		return vulnerabilities, err
	}

	err = knowledge.ScanRows(ctx, rows, &vulnerabilities)
	if err != nil {
		log.Printf("Error scanning GCVE rows: %v", err)
		return vulnerabilities, err
	}

	return vulnerabilities, nil
}

// GetVulnByCVEId retrieves a GCVE record by its CVE ID for cross-referencing.
func GetVulnByCVEId(cveId string, knowledge *bun.DB) (*knowledge_db.GCVEItem, error) {
	if knowledge == nil {
		return nil, nil
	}

	ctx := context.Background()
	item := &knowledge_db.GCVEItem{}
	err := knowledge.NewSelect().Model(item).Where("cve_id = ?", cveId).Limit(1).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return item, nil
}
