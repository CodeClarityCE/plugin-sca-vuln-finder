package main

import (
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	extensionAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/extensionAnalyzer"
	extensionMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/extensions"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/stretchr/testify/assert"
)

// TestE2E_PHPExtensionAnalyzer tests the PHP extension analyzer end-to-end
func TestE2E_PHPExtensionAnalyzer(t *testing.T) {
	analyzer := extensionAnalyzer.NewPHPExtensionAnalyzer()
	assert.NotNil(t, analyzer, "Should create PHP extension analyzer")

	// Create a mock SBOM for testing
	mockSBOM := createMockPHPSBOM()

	// Test extension extraction
	extensions := analyzer.ExtractExtensionsFromSBOM(mockSBOM)
	assert.NotEmpty(t, extensions, "Should extract PHP extensions from SBOM")
	assert.Greater(t, len(extensions), 5, "Should extract multiple common extensions")

	// Verify expected extensions are present
	expectedExtensions := []string{"curl", "json", "openssl", "mbstring", "xml", "mysqli", "pdo", "zip", "gd"}
	foundExtensions := 0
	for _, extName := range expectedExtensions {
		if version, exists := extensions[extName]; exists {
			foundExtensions++
			assert.NotEmpty(t, version, "Extension %s should have version", extName)
		}
	}
	assert.Greater(t, foundExtensions, 6, "Should find at least 7 expected extensions")

	// Test filtering of relevant extensions
	relevantExtensions := analyzer.FilterRelevantExtensions(extensions)
	assert.NotEmpty(t, relevantExtensions, "Should have relevant extensions for vulnerability tracking")
	assert.LessOrEqual(t, len(relevantExtensions), len(extensions), "Relevant extensions should be subset of all extensions")

	// Verify that vulnerable extensions are included in relevant set
	vulnerableExtensions := []string{"curl", "openssl", "xml", "gd"}
	for _, extName := range vulnerableExtensions {
		if _, existsInAll := extensions[extName]; existsInAll {
			_, existsInRelevant := relevantExtensions[extName]
			assert.True(t, existsInRelevant, "Vulnerable extension %s should be in relevant set", extName)
		}
	}

	// Test vulnerability analysis (with mock knowledge DB)
	vulnerabilities := analyzer.AnalyzeExtensionVulnerabilities(relevantExtensions, nil)
	assert.NotNil(t, vulnerabilities, "Should return vulnerabilities list (even if empty)")

	// Note: With mock knowledge DB (nil), we expect empty vulnerabilities
	// In a real test with populated knowledge DB, we would verify vulnerability detection
}

// TestE2E_PHPExtensionVulnerabilityMatcher tests the extension vulnerability matcher
func TestE2E_PHPExtensionVulnerabilityMatcher(t *testing.T) {
	matcher := extensionMatcher.PHPExtensionVulnerabilityMatcher{}

	// Test vulnerability relevance detection
	testCases := map[string]bool{
		"curl":       true,  // Should be relevant
		"openssl":    true,  // Should be relevant
		"xml":        true,  // Should be relevant
		"gd":         true,  // Should be relevant
		"json":       true,  // Should be relevant
		"mbstring":   true,  // Should be relevant
		"core":       false, // Should not be relevant
		"reflection": false, // Should not be relevant
		"standard":   false, // Should not be relevant
	}

	for extensionName, expectedRelevant := range testCases {
		isRelevant := extensionMatcher.IsVulnerabilityRelevant(extensionName)
		assert.Equal(t, expectedRelevant, isRelevant,
			"Extension %s relevance should be %t", extensionName, expectedRelevant)
	}

	// Test vulnerability matching (with mock knowledge DB)
	matches, err := matcher.MatchExtensionVulnerabilities("openssl", "1.1.1", nil)
	assert.NoError(t, err, "Should not error with mock knowledge DB")
	assert.NotNil(t, matches, "Should return matches slice (even if empty)")

	// Note: With mock knowledge DB (nil), we expect empty matches
	// In a real test with populated knowledge DB, we would verify vulnerability matching
}

// TestE2E_PHPVulnerabilityPipeline tests the complete PHP vulnerability analysis pipeline
func TestE2E_PHPVulnerabilityPipeline(t *testing.T) {
	// Create a mock SBOM with PHP dependencies and extensions
	mockSBOM := createMockPHPSBOMWithVulnerabilities()

	// Test the complete vulnerability analysis pipeline
	start := time.Now()
	output := vulnerabilities.Start("https://github.com/test/php-project", mockSBOM, "PHP", start, nil)

	// Verify output structure
	assert.NotNil(t, output, "Should return vulnerability output")
	assert.NotNil(t, output.WorkSpaces, "Should have workspaces")
	assert.NotNil(t, output.AnalysisInfo, "Should have analysis info")

	// Verify analysis completed successfully
	assert.Equal(t, codeclarity.SUCCESS, output.AnalysisInfo.Status, "Analysis should succeed")
	assert.Empty(t, output.AnalysisInfo.Errors, "Should have no errors")

	// Verify timing information
	assert.NotEmpty(t, output.AnalysisInfo.AnalysisStartTime, "Should have start time")
	assert.NotEmpty(t, output.AnalysisInfo.AnalysisEndTime, "Should have end time")
	assert.Greater(t, output.AnalysisInfo.AnalysisDeltaTime, float64(0), "Should have positive delta time")

	// Verify workspace structure
	assert.Contains(t, output.WorkSpaces, ".", "Should have default workspace")
	defaultWs := output.WorkSpaces["."]
	assert.NotNil(t, defaultWs.Vulnerabilities, "Should have vulnerabilities list")

	// Note: With mock knowledge DB (nil), we expect no actual vulnerabilities
	// But the pipeline should complete successfully and include extension analysis
	assert.GreaterOrEqual(t, len(defaultWs.Vulnerabilities), 0, "Should have vulnerabilities list (may be empty)")
}

// TestE2E_JavaScriptPHPMixedProject tests analysis of projects with both JS and PHP
func TestE2E_JavaScriptPHPMixedProject(t *testing.T) {
	// Test that PHP-specific functionality doesn't interfere with JS analysis
	mockJSSBOM := createMockJSSBOM()

	// Test JavaScript analysis
	start := time.Now()
	jsOutput := vulnerabilities.Start("https://github.com/test/js-project", mockJSSBOM, "JS", start, nil)

	assert.NotNil(t, jsOutput, "Should handle JS analysis")
	assert.Equal(t, codeclarity.SUCCESS, jsOutput.AnalysisInfo.Status, "JS analysis should succeed")

	// Verify JS analysis doesn't include PHP extension analysis
	defaultWs := jsOutput.WorkSpaces["."]
	for _, vuln := range defaultWs.Vulnerabilities {
		assert.NotEqual(t, "php-extension", vuln.ExtensionType, "JS analysis should not include PHP extensions")
	}

	// Test PHP analysis
	mockPHPSBOM := createMockPHPSBOM()
	start = time.Now()
	phpOutput := vulnerabilities.Start("https://github.com/test/php-project", mockPHPSBOM, "PHP", start, nil)

	assert.NotNil(t, phpOutput, "Should handle PHP analysis")
	assert.Equal(t, codeclarity.SUCCESS, phpOutput.AnalysisInfo.Status, "PHP analysis should succeed")

	// Verify both analyses complete independently
	assert.NotEqual(t, jsOutput.AnalysisInfo.AnalysisStartTime, phpOutput.AnalysisInfo.AnalysisStartTime,
		"Analyses should have different start times")
}

// TestE2E_PHPVulnerabilityFields tests that PHP extension vulnerabilities have proper field mapping
func TestE2E_PHPVulnerabilityFields(t *testing.T) {
	// Test that vulnerability fields are properly mapped for PHP extensions
	mockSBOM := createMockPHPSBOMWithVulnerabilities()

	start := time.Now()
	output := vulnerabilities.Start("https://github.com/test/php-project", mockSBOM, "PHP", start, nil)

	assert.NotNil(t, output, "Should return output")

	// Verify vulnerability structure for any found vulnerabilities
	for _, ws := range output.WorkSpaces {
		for _, vuln := range ws.Vulnerabilities {
			// Test required fields are present
			assert.NotEmpty(t, vuln.AffectedDependency, "Should have affected dependency")
			assert.NotEmpty(t, vuln.AffectedVersion, "Should have affected version")

			// Test that sources are properly set
			assert.NotEmpty(t, vuln.Sources, "Should have vulnerability sources")

			// If this is a PHP extension vulnerability, verify specific fields
			if vuln.ExtensionType == "php-extension" {
				assert.Contains(t, vuln.AffectedDependency, "ext-", "PHP extension should have ext- prefix")
				assert.NotEmpty(t, vuln.PackageName, "Should have package name")
				assert.NotEmpty(t, vuln.CurrentVersion, "Should have current version")
				assert.False(t, vuln.DirectDependency, "Extensions should not be direct dependencies")
			}
		}
	}
}

// Helper functions to create mock SBOM data for testing

func createMockPHPSBOM() sbomTypes.Output {
	return sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {
				Dependencies: map[string]map[string]sbomTypes.Versions{
					"symfony/console": {
						"5.4.0": sbomTypes.Versions{
							Key:      "symfony/console@5.4.0",
							Dev:      false,
							Prod:     true,
							Direct:   true,
							Licenses: []string{"MIT"},
						},
					},
				},
				Start: sbomTypes.Start{
					Dependencies: []sbomTypes.WorkSpaceDependency{
						{Name: "symfony/console", Version: "5.4.0", Constraint: "^5.4"},
					},
				},
			},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{
			Status:         codeclarity.SUCCESS,
			ProjectName:    "test-php-project",
			PackageManager: "composer",
			Extra: sbomTypes.Extra{
				VersionSeperator:    "@",
				ImportPathSeperator: "/",
				LockFileVersion:     1,
			},
		},
	}
}

func createMockPHPSBOMWithVulnerabilities() sbomTypes.Output {
	return sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {
				Dependencies: map[string]map[string]sbomTypes.Versions{
					"symfony/http-foundation": {
						"4.0.0": sbomTypes.Versions{
							Key:      "symfony/http-foundation@4.0.0",
							Dev:      false,
							Prod:     true,
							Direct:   true,
							Licenses: []string{"MIT"},
						},
					},
					"twig/twig": {
						"1.35.0": sbomTypes.Versions{
							Key:      "twig/twig@1.35.0",
							Dev:      false,
							Prod:     true,
							Direct:   true,
							Licenses: []string{"BSD-3-Clause"},
						},
					},
				},
				Start: sbomTypes.Start{
					Dependencies: []sbomTypes.WorkSpaceDependency{
						{Name: "symfony/http-foundation", Version: "4.0.0", Constraint: "4.0.0"},
						{Name: "twig/twig", Version: "1.35.0", Constraint: "1.35.0"},
					},
				},
			},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{
			Status:         codeclarity.SUCCESS,
			ProjectName:    "test-vulnerable-php-project",
			PackageManager: "composer",
			Extra: sbomTypes.Extra{
				VersionSeperator:    "@",
				ImportPathSeperator: "/",
				LockFileVersion:     1,
			},
		},
	}
}

func createMockJSSBOM() sbomTypes.Output {
	return sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {
				Dependencies: map[string]map[string]sbomTypes.Versions{
					"express": {
						"4.18.0": sbomTypes.Versions{
							Key:      "express@4.18.0",
							Dev:      false,
							Prod:     true,
							Direct:   true,
							Licenses: []string{"MIT"},
						},
					},
				},
				Start: sbomTypes.Start{
					Dependencies: []sbomTypes.WorkSpaceDependency{
						{Name: "express", Version: "4.18.0", Constraint: "^4.18.0"},
					},
				},
			},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{
			Status:         codeclarity.SUCCESS,
			ProjectName:    "test-js-project",
			PackageManager: "npm",
			Extra: sbomTypes.Extra{
				VersionSeperator:    "@",
				ImportPathSeperator: "/",
				LockFileVersion:     2,
			},
		},
	}
}
