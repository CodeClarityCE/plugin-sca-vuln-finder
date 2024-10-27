package cwe

import (
	"context"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// GetCWE retrieves a CWEEntry from the database based on the provided CWE ID.
// It returns the CWEEntry and an error if any occurred.
func GetCWE(cweId string, knowledge *bun.DB) (knowledge_db.CWEEntry, error) {
	var cwe knowledge_db.CWEEntry

	err := knowledge.NewSelect().Model(&cwe).Where("cwe_id = ?", cweId).Scan(context.Background())
	if err != nil {
		return cwe, err
	}

	return cwe, nil

}
