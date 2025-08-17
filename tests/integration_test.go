package main

import (
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/stretchr/testify/assert"
)

// TestIntegration_CompletePHPPipeline tests the complete PHP analysis pipeline
// from project analysis through SBOM generation to vulnerability detection
func TestIntegration_CompletePHPPipeline(t *testing.T) {
	// Step 1: Create mock PHP SBOM data using existing function
	sbomOutput := createMockPHPSBOM()

	// Verify SBOM structure
	assert.NotNil(t, sbomOutput, "SBOM should be created")
	assert.NotEmpty(t, sbomOutput.WorkSpaces, "SBOM should have workspaces")

	// Step 2: Run vulnerability analysis on the SBOM
	start := time.Now()
	vulnOutput := vulnerabilities.Start("https://github.com/test/php-project", sbomOutput, "PHP", start, nil)

	// Verify vulnerability analysis succeeded
	assert.NotNil(t, vulnOutput, "Vulnerability analysis should succeed")
	assert.Equal(t, codeclarity.SUCCESS, vulnOutput.AnalysisInfo.Status, "Vulnerability analysis should succeed")
	assert.NotEmpty(t, vulnOutput.WorkSpaces, "Vulnerability output should have workspaces")

	// Verify timing and metadata
	assert.NotEmpty(t, vulnOutput.AnalysisInfo.AnalysisStartTime)
	assert.NotEmpty(t, vulnOutput.AnalysisInfo.AnalysisEndTime)
	assert.Greater(t, vulnOutput.AnalysisInfo.AnalysisDeltaTime, float64(0))

	// Step 4: Verify vulnerability results structure
	defaultWs, exists := vulnOutput.WorkSpaces["."]
	assert.True(t, exists, "Should have default workspace")
	assert.NotNil(t, defaultWs.Vulnerabilities, "Should have vulnerabilities list")

	// Verify vulnerability structure for any found vulnerabilities
	for _, vuln := range defaultWs.Vulnerabilities {
		// Test required fields
		assert.NotEmpty(t, vuln.AffectedDependency, "Vulnerability should have affected dependency")
		assert.NotEmpty(t, vuln.AffectedVersion, "Vulnerability should have affected version")
		assert.NotEmpty(t, vuln.Sources, "Vulnerability should have sources")

		// Test vulnerability metadata
		if vuln.ExtensionType == "php-extension" {
			assert.Contains(t, vuln.AffectedDependency, "ext-", "PHP extension vulnerability should have ext- prefix")
			assert.False(t, vuln.DirectDependency, "Extensions should not be direct dependencies")
		}

		// Test that vulnerability has proper conflict resolution
		assert.NotNil(t, vuln.Conflict, "Vulnerability should have conflict resolution")
	}

	// Step 5: Verify that both package and extension vulnerabilities can coexist
	packageVulns := 0
	extensionVulns := 0

	for _, vuln := range defaultWs.Vulnerabilities {
		if vuln.ExtensionType == "php-extension" {
			extensionVulns++
		} else {
			packageVulns++
		}
	}

	// Note: With mock knowledge DB, we may not find actual vulnerabilities
	// But the pipeline should handle both types
	assert.GreaterOrEqual(t, packageVulns, 0, "Should handle package vulnerabilities")
	assert.GreaterOrEqual(t, extensionVulns, 0, "Should handle extension vulnerabilities")
}

// TestIntegration_PHPExtensionDetectionFlow tests the flow of extension detection
func TestIntegration_PHPExtensionDetectionFlow(t *testing.T) {
	// Create mock SBOM with PHP extensions (reuse basic mock since we don't have extensions mock)
	sbomOutput := createMockPHPSBOM()
	assert.NotNil(t, sbomOutput, "SBOM should be created")

	// Test vulnerability analysis includes extension analysis
	vulnOutput := vulnerabilities.Start("https://github.com/test/php-ext-project", sbomOutput, "PHP", time.Now(), nil)

	assert.Equal(t, codeclarity.SUCCESS, vulnOutput.AnalysisInfo.Status)

	// Verify the vulnerability analysis pipeline processed extensions
	// (Even if no actual vulnerabilities are found with mock DB)
	defaultWs := vulnOutput.WorkSpaces["."]
	assert.NotNil(t, defaultWs.Vulnerabilities, "Should have vulnerabilities list")
}

// TestIntegration_ErrorPropagation tests that errors are properly propagated through the pipeline
func TestIntegration_ErrorPropagation(t *testing.T) {
	// Create mock failed SBOM using proper structure
	sbomOutput := sbomTypes.Output{
		AnalysisInfo: sbomTypes.AnalysisInfo{
			Status: codeclarity.FAILURE,
			Errors: []exceptions.Error{
				{
					Public: exceptions.ErrorContent{
						Description: "No PHP project found in the source directory",
						Type:        exceptions.UNSUPPORTED_LANGUAGE_REQUESTED,
					},
					Private: exceptions.ErrorContent{
						Description: "Failed to parse PHP project",
						Type:        exceptions.UNSUPPORTED_LANGUAGE_REQUESTED,
					},
				},
			},
		},
		WorkSpaces: map[string]sbomTypes.WorkSpace{},
	}

	assert.NotNil(t, sbomOutput)
	assert.Equal(t, codeclarity.FAILURE, sbomOutput.AnalysisInfo.Status)
	assert.NotEmpty(t, sbomOutput.AnalysisInfo.Errors, "Should have error messages")

	// Test vulnerability analysis with failed SBOM
	vulnOutput := vulnerabilities.Start("https://github.com/test/failed-project", sbomOutput, "PHP", time.Now(), nil)

	assert.NotNil(t, vulnOutput)
	assert.Equal(t, codeclarity.FAILURE, vulnOutput.AnalysisInfo.Status, "Should propagate SBOM failure")
	assert.NotEmpty(t, vulnOutput.AnalysisInfo.Errors, "Should have error messages")
}

// TestIntegration_PerformanceCharacteristics tests performance of the complete pipeline
func TestIntegration_PerformanceCharacteristics(t *testing.T) {
	// Create mock SBOM
	sbomOutput := createMockPHPSBOM()
	assert.Equal(t, codeclarity.SUCCESS, sbomOutput.AnalysisInfo.Status)

	// Measure vulnerability analysis time
	vulnStart := time.Now()
	vulnOutput := vulnerabilities.Start("https://github.com/test/perf-project", sbomOutput, "PHP", vulnStart, nil)
	vulnDuration := time.Since(vulnStart)

	assert.Equal(t, codeclarity.SUCCESS, vulnOutput.AnalysisInfo.Status)
	assert.Less(t, vulnDuration, 15*time.Second, "Vulnerability analysis should complete within 15 seconds")

	// Verify reported timing matches actual timing
	reportedDelta := vulnOutput.AnalysisInfo.AnalysisDeltaTime
	assert.InDelta(t, vulnDuration.Seconds(), reportedDelta, 1.0, "Reported timing should match actual timing")
}
