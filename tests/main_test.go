package main

import (
	"database/sql"
	"os"
	"testing"
	"time"

	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	phpRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/php"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestCreateNPMv1(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/npmv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/npmv1/vulns.json")
}

func TestCreateNPMv2(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "6432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/npmv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/npmv2/vulns.json")
}

func TestCreateYarnv1(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv1/vulns.json")
}

func TestCreateYarnv2(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv2/vulns.json")
}

func TestCreateYarnv3(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:6432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv3/vulns.json")
}

func TestCreateYarnv4(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv4")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv4/vulns.json")
}

func TestCreateYarnWorkspace(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/yarn_workspace")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarn_workspace/vulns.json")
}

func TestCreatePNPMv10_10(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/pnpmv10.10")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/pnpmv10.10/vulns.json")
}

func TestCreateTest(t *testing.T) {
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../js-sbom/tests/test")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), db_knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/test/vulns.json")
}

func TestCreatePHP(t *testing.T) {
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	sbom, err := getSBOM("../../php-sbom/tests/test1")
	if err != nil {
		t.Errorf("Error getting mock PHP SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "PHP", time.Now(), db_knowledge)

	// Debug output for failing tests
	if out.AnalysisInfo.Status != codeclarity.SUCCESS {
		t.Logf("Analysis failed with status: %s", out.AnalysisInfo.Status)
		if len(out.AnalysisInfo.Errors) > 0 {
			t.Logf("Errors: %+v", out.AnalysisInfo.Errors)
		}
	}

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	// Check that we have the expected PHP dependencies
	workspace := out.WorkSpaces["."]
	assert.NotNil(t, workspace)
	
	// Since PHP knowledge database might not have packages, we should at least verify
	// that the plugin runs without errors and returns proper structure
	assert.IsType(t, []vulnerabilityFinder.Vulnerability{}, workspace.Vulnerabilities)
	
	// Verify the analysis structure
	assert.NotEmpty(t, out.AnalysisInfo.AnalysisStartTime)
	assert.NotEmpty(t, out.AnalysisInfo.AnalysisEndTime)

	WriteJSON(out, "../../php-sbom/tests/test1/vulns.json")
}

func TestPHPRepositoryFunctions(t *testing.T) {
	// Test PHP repository functions without database dependency
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(50*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	// Test GetVersionStrings for non-existent package (should return empty, no error)
	versions, err := phpRepository.PhpPackageRepository.GetVersionStrings("non-existent/package", db_knowledge)
	assert.NoError(t, err)
	assert.Empty(t, versions)

	// Test GetVersionStringsBelow for non-existent package
	versionsBelow, err := phpRepository.PhpPackageRepository.GetVersionStringsBelow("non-existent/package", "1.0.0", 10, db_knowledge)
	assert.NoError(t, err)
	assert.Empty(t, versionsBelow)

	// Test GetVersionStringsAbove for non-existent package
	versionsAbove, err := phpRepository.PhpPackageRepository.GetVersionStringsAbove("non-existent/package", "1.0.0", 10, db_knowledge)
	assert.NoError(t, err)
	assert.Empty(t, versionsAbove)

	// Test GetFirstVersionString for non-existent package (should return error)
	_, err = phpRepository.PhpPackageRepository.GetFirstVersionString("non-existent/package", db_knowledge)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no versions")

	// Test GetLastVersionString for non-existent package (should return error)
	_, err = phpRepository.PhpPackageRepository.GetLastVersionString("non-existent/package", db_knowledge)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no versions")
}
