package cwe

import (
	"database/sql"
	"testing"

	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestGetCWE(t *testing.T) {
	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	// Call the GetCWE function
	cwe, err := GetCWE("123", db_knowledge)

	// Assert the expected values
	assert.NoError(t, err)
	assert.Equal(t, db_knowledge, cwe)
}
