package main

import (
	"database/sql"
	"os"
	"testing"
	"time"

	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestLanguageDetection(t *testing.T) {
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	t.Run("JavaScript Language Detection", func(t *testing.T) {
		sbom, err := getSBOM("../../../js-sbom/tests/npmv1")
		if err != nil {
			t.Skip("Skipping JS test - SBOM file not found")
			return
		}

		out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)
		
		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
		assert.NotEmpty(t, out.WorkSpaces)
	})

	t.Run("PHP Language Detection", func(t *testing.T) {
		sbom, err := getSBOM("php")
		if err != nil {
			t.Errorf("Error getting PHP SBOM: %v", err)
			return
		}

		out := vulnerabilities.Start("", sbom, "PHP", time.Now(), db_knowledge)
		
		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
		assert.NotEmpty(t, out.WorkSpaces)
		
		// Verify it handles PHP packages without crashing
		workspace := out.WorkSpaces["."]
		assert.NotNil(t, workspace)
		assert.IsType(t, []interface{}{}, workspace.Vulnerabilities)
	})

	t.Run("Unsupported Language", func(t *testing.T) {
		sbom, err := getSBOM("php")
		if err != nil {
			t.Errorf("Error getting PHP SBOM: %v", err)
			return
		}

		out := vulnerabilities.Start("", sbom, "PYTHON", time.Now(), db_knowledge)
		
		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.FAILURE, out.AnalysisInfo.Status)
		assert.NotEmpty(t, out.AnalysisInfo.Errors)
	})
}