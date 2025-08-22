package main

import (
	"os"
	"testing"
	"time"

	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	phpRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/php"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/boilerplates"
	"github.com/stretchr/testify/assert"
)

// setupTestEnvironment sets up the necessary environment for testing
func setupTestEnvironment(t *testing.T) (*boilerplates.PluginBase, func()) {
	// Set test database environment
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")
	os.Setenv("NPM_URL", "https://replicate.npmjs.com/")

	// Create PluginBase for testing
	pluginBase, err := boilerplates.CreatePluginBase()
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		pluginBase.Close()
	}

	return pluginBase, cleanup
}

func TestCreateNPMv1(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/npmv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/npmv1/vulns.json")
}

func TestCreateNPMv2(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/npmv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/npmv2/vulns.json")
}

func TestCreateYarnv1(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv1")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv1/vulns.json")
}

func TestCreateYarnv2(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv2")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv2/vulns.json")
}

func TestCreateYarnv3(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv3")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv3/vulns.json")
}

func TestCreateYarnv4(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/yarnv4")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarnv4/vulns.json")
}

func TestCreateYarnWorkspace(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/yarn_workspace")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/yarn_workspace/vulns.json")
}

func TestCreatePNPMv10_10(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/pnpmv10.10")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/pnpmv10.10/vulns.json")
}

func TestCreateTest(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../js-sbom/tests/test")
	if err != nil {
		t.Errorf("Error getting mock SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "JS", time.Now(), pluginBase.DB.Knowledge)

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)

	WriteJSON(out, "../../js-sbom/tests/test/vulns.json")
}

func TestCreatePHP(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../php-sbom/tests/test1")
	if err != nil {
		t.Errorf("Error getting mock PHP SBOM: %v", err)
	}

	out := vulnerabilities.Start("", sbom, "PHP", time.Now(), pluginBase.DB.Knowledge)

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

func TestCreatePHPCachet(t *testing.T) {
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	sbom, err := getSBOM("../../php-sbom/tests/test8-cachet")
	if err != nil {
		t.Errorf("Error getting Cachet PHP SBOM: %v", err)
	}

	// Debug: Log SBOM structure
	t.Logf("SBOM Project Name: %s", sbom.AnalysisInfo.ProjectName)
	t.Logf("SBOM Package Manager: %s", sbom.AnalysisInfo.PackageManager)
	if workspace, exists := sbom.WorkSpaces["."]; exists {
		t.Logf("Dependencies count: %d", len(workspace.Dependencies))
		// Log first few dependencies
		count := 0
		for depName, depVersions := range workspace.Dependencies {
			if count >= 5 {
				break
			}
			for version := range depVersions {
				t.Logf("Dependency: %s@%s", depName, version)
				break
			}
			count++
		}
	}

	// Debug: Log a few key dependencies to see what's being processed
	if workspace, exists := sbom.WorkSpaces["."]; exists {
		count := 0
		for depName, depVersions := range workspace.Dependencies {
			if count >= 10 {
				break
			}
			for version := range depVersions {
				t.Logf("Processing dependency: %s@%s", depName, version)
				break
			}
			count++
		}
	}

	out := vulnerabilities.Start("", sbom, "PHP", time.Now(), pluginBase.DB.Knowledge)

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

	// Check that we have the expected workspace
	workspace := out.WorkSpaces["."]
	assert.NotNil(t, workspace)

	// Log vulnerability analysis results
	t.Logf("Found %d vulnerabilities", len(workspace.Vulnerabilities))
	
	// Print first few vulnerabilities for debugging
	for i, vuln := range workspace.Vulnerabilities {
		if i >= 5 {
			break
		}
		t.Logf("Vulnerability %d: %s in %s@%s (Severity: %v)", 
			i+1, vuln.VulnerabilityId, vuln.AffectedDependency, vuln.AffectedVersion, vuln.Severity)
	}

	// Verify the analysis structure
	assert.IsType(t, []vulnerabilityFinder.Vulnerability{}, workspace.Vulnerabilities)
	assert.NotEmpty(t, out.AnalysisInfo.AnalysisStartTime)
	assert.NotEmpty(t, out.AnalysisInfo.AnalysisEndTime)

	// Test Cachet-specific expectations (from input SBOM)
	assert.Equal(t, "cachethq/cachet", sbom.AnalysisInfo.ProjectName)
	assert.Equal(t, "composer", string(sbom.AnalysisInfo.PackageManager))

	// Since this is a real project with many dependencies, we expect to find vulnerabilities
	// Note: This may fail if the knowledge database is not populated with PHP vulnerabilities
	if len(workspace.Vulnerabilities) == 0 {
		t.Logf("Warning: No vulnerabilities found - knowledge database may not be populated with PHP/OSV data")
	}

	WriteJSON(out, "../../php-sbom/tests/test8-cachet/vulns.json")
}

func TestPHPRepositoryFunctions(t *testing.T) {
	// Test PHP repository functions without database dependency
	pluginBase, cleanup := setupTestEnvironment(t)
	if pluginBase == nil {
		return // Test was skipped
	}
	defer cleanup()

	// Test GetVersionStrings for non-existent package (should return empty, no error)
	versions, err := phpRepository.PhpPackageRepository.GetVersionStrings("non-existent/package", pluginBase.DB.Knowledge)
	assert.NoError(t, err)
	assert.Empty(t, versions)

	// Test GetVersionStringsBelow for non-existent package
	versionsBelow, err := phpRepository.PhpPackageRepository.GetVersionStringsBelow("non-existent/package", "1.0.0", 10, pluginBase.DB.Knowledge)
	assert.NoError(t, err)
	assert.Empty(t, versionsBelow)

	// Test GetVersionStringsAbove for non-existent package
	versionsAbove, err := phpRepository.PhpPackageRepository.GetVersionStringsAbove("non-existent/package", "1.0.0", 10, pluginBase.DB.Knowledge)
	assert.NoError(t, err)
	assert.Empty(t, versionsAbove)

	// Test GetFirstVersionString for non-existent package (should return error)
	_, err = phpRepository.PhpPackageRepository.GetFirstVersionString("non-existent/package", pluginBase.DB.Knowledge)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no versions")

	// Test GetLastVersionString for non-existent package (should return error)
	_, err = phpRepository.PhpPackageRepository.GetLastVersionString("non-existent/package", pluginBase.DB.Knowledge)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no versions")
}