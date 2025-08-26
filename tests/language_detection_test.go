package main

import (
	"os"
	"testing"
	"time"

	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	"github.com/CodeClarityCE/utility-boilerplates"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/stretchr/testify/assert"
)

func TestLanguageDetection(t *testing.T) {
	// Set test database environment
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	// Create PluginBase for testing
	pluginBase, err := boilerplates.CreatePluginBase()
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
		return
	}
	defer pluginBase.Close()

	t.Run("JavaScript Language Detection", func(t *testing.T) {
		sbom, err := getSBOM("../../js-sbom/tests/npmv1")
		if err != nil {
			t.Skip("Skipping JS test - SBOM file not found")
			return
		}

		out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
		assert.NotEmpty(t, out.WorkSpaces)
	})

	t.Run("PHP Language Detection", func(t *testing.T) {
		sbom, err := getSBOM("../../php-sbom/tests/test1")
		if err != nil {
			t.Errorf("Error getting PHP SBOM: %v", err)
			return
		}

		out := vulnerabilities.Start("", sbom, "PHP", time.Now(), pluginBase.DB.Knowledge)

		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
		assert.NotEmpty(t, out.WorkSpaces)

		// Verify it handles PHP packages without crashing
		workspace := out.WorkSpaces["."]
		assert.NotNil(t, workspace)
		// Vulnerabilities should be a valid slice, regardless of the specific type
		assert.NotNil(t, workspace.Vulnerabilities)
	})

	t.Run("Unsupported Language", func(t *testing.T) {
		sbom, err := getSBOM("../../php-sbom/tests/test1")
		if err != nil {
			t.Errorf("Error getting PHP SBOM: %v", err)
			return
		}

		out := vulnerabilities.Start("", sbom, "PYTHON", time.Now(), pluginBase.DB.Knowledge)

		assert.NotNil(t, out)
		assert.Equal(t, codeclarity.FAILURE, out.AnalysisInfo.Status)
		assert.NotEmpty(t, out.AnalysisInfo.Errors)
	})
}
