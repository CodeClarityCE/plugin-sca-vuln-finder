package cwe

import (
	"context"
	"testing"

	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCWE(t *testing.T) {
	ctx := context.Background()
	db := testdeps.Postgres(t)
	_, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`)
	require.NoError(t, err)
	_, err = db.NewCreateTable().Model((*knowledge_db.CWEEntry)(nil)).Exec(ctx)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO cwe (cwe_id, name) VALUES ('123', 'Write-what-where Condition')`)
	require.NoError(t, err)

	cwe, err := GetCWE("123", db)

	assert.NoError(t, err)
	assert.Equal(t, "123", cwe.CWEId)
	assert.Equal(t, "Write-what-where Condition", cwe.Name)
}
