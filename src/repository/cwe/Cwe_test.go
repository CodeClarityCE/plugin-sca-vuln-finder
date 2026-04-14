package cwe

import (
	"database/sql"
	"os"
	"testing"

	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestGetCWE(t *testing.T) {
	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		port = "5432"
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		user = "postgres"
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		t.Skip("PG_DB_PASSWORD not set, skipping")
	}

	dsn_knowledge := dbhelper.BuildDSN(user, password, host, port, dbhelper.Config.Database.Knowledge)
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	// Skip if database is not available
	if err := sqldb_knowledge.Ping(); err != nil {
		t.Skipf("Knowledge database not available, skipping: %v", err)
	}

	// Call the GetCWE function
	cwe, err := GetCWE("123", db_knowledge)

	// Assert the expected values
	assert.NoError(t, err)
	assert.Equal(t, "123", cwe.CWEId)
	assert.NotEmpty(t, cwe.Name)
}
