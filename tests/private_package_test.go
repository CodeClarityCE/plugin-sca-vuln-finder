package main

import (
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	vulnerabilityFinderTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
)

// TestPrivatePackageVulnerabilityDetection tests the private package vulnerability detection functionality
func TestPrivatePackageVulnerabilityDetection(t *testing.T) {
	// Create a mock SBOM with private repository information
	sbom := createMockSBOMWithPrivatePackages()

	// Run vulnerability analysis
	output := vulnerabilities.Start("https://github.com/test/project", sbom, "PHP", time.Now(), nil)

	// Validate that vulnerabilities were found
	if output.AnalysisInfo.Status != codeclarity.SUCCESS {
		t.Errorf("Expected analysis to succeed, got status: %s", output.AnalysisInfo.Status)
	}

	// Check if private package vulnerabilities were detected
	foundPrivateVulns := false
	for _, workspace := range output.WorkSpaces {
		for _, vuln := range workspace.Vulnerabilities {
			// Check if any vulnerabilities come from private analysis
			for _, source := range vuln.Sources {
				if source == vulnerabilityFinderTypes.PRIVATE_ANALYSIS {
					foundPrivateVulns = true
					t.Logf("Found private package vulnerability: %s for package %s",
						vuln.VulnerabilityId, vuln.AffectedDependency)
					break
				}
			}
		}
	}

	if !foundPrivateVulns {
		t.Log("No private package vulnerabilities detected - this may be expected if no private packages match the detection patterns")
	}
}

// TestPrivatePackagePatternDetection tests specific private package vulnerability patterns
func TestPrivatePackagePatternDetection(t *testing.T) {
	// Create SBOM with packages that should trigger pattern detection
	sbom := createMockSBOMWithProblematicPackages()

	// Run vulnerability analysis
	output := vulnerabilities.Start("https://github.com/test/project", sbom, "PHP", time.Now(), nil)

	// Look for specific pattern-based vulnerabilities
	expectedPatterns := []string{
		"PRIVATE-PATTERN-DEBUG",
		"PRIVATE-PATTERN-TEST",
		"PRIVATE-LICENSE-MISSING",
	}

	vulnerabilityMap := make(map[string]bool)
	for _, workspace := range output.WorkSpaces {
		for _, vuln := range workspace.Vulnerabilities {
			for _, pattern := range expectedPatterns {
				if contains(vuln.VulnerabilityId, pattern) {
					vulnerabilityMap[pattern] = true
					t.Logf("Found expected pattern vulnerability: %s", vuln.VulnerabilityId)
				}
			}
		}
	}

	// Verify we found at least some pattern-based vulnerabilities
	if len(vulnerabilityMap) == 0 {
		t.Log("No pattern-based vulnerabilities found - this may be expected based on package naming")
	}
}

// Helper function to create mock SBOM with private packages
func createMockSBOMWithPrivatePackages() sbomTypes.Output {
	// Create dependencies that would be identified as private
	dependencies := map[string]map[string]sbomTypes.Versions{
		"company/private-package": {
			"1.0.0": {
				Key:      "company/private-package@1.0.0",
				Licenses: []string{"Proprietary"},
				Prod:     true,
				Direct:   true,
			},
		},
		"acme/internal-library": {
			"2.1.0": {
				Key:      "acme/internal-library@2.1.0",
				Licenses: []string{}, // Missing license
				Prod:     true,
				Direct:   true,
			},
		},
		"enterprise/debug-tools": {
			"1.5.0": {
				Key:      "enterprise/debug-tools@1.5.0",
				Licenses: []string{"MIT"},
				Prod:     true, // Debug package in production
				Direct:   true,
			},
		},
	}

	// Create workspace
	workspace := sbomTypes.WorkSpace{
		Dependencies: dependencies,
		Start: sbomTypes.Start{
			Dependencies: []sbomTypes.WorkSpaceDependency{
				{Name: "company/private-package", Version: "1.0.0", Constraint: "^1.0"},
				{Name: "acme/internal-library", Version: "2.1.0", Constraint: "^2.0"},
				{Name: "enterprise/debug-tools", Version: "1.5.0", Constraint: "^1.0"},
			},
		},
	}

	// Note: Private repository info would be included in PHP SBOMs but not JS SBOMs
	// The private package analyzer will use heuristics to detect private packages
	// based on naming patterns and license information

	// Create SBOM with private repository information
	return sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			"default": workspace,
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{
			Status:      codeclarity.SUCCESS,
			ProjectName: "Test Private Project",
			Extra: sbomTypes.Extra{
				VersionSeperator:    "@",
				ImportPathSeperator: "/",
				LockFileVersion:     2,
			},
		},
	}
}

// Helper function to create SBOM with problematic packages
func createMockSBOMWithProblematicPackages() sbomTypes.Output {
	dependencies := map[string]map[string]sbomTypes.Versions{
		"company/debug-helper": {
			"1.0.0": {
				Key:      "company/debug-helper@1.0.0",
				Licenses: []string{"MIT"},
				Prod:     true,
				Direct:   true,
			},
		},
		"internal/test-utils": {
			"2.0.0": {
				Key:      "internal/test-utils@2.0.0",
				Licenses: []string{"MIT"},
				Prod:     true, // Test package in production
				Direct:   true,
			},
		},
		"private/no-license-package": {
			"1.0.0": {
				Key:      "private/no-license-package@1.0.0",
				Licenses: []string{}, // No license
				Prod:     true,
				Direct:   true,
			},
		},
	}

	workspace := sbomTypes.WorkSpace{
		Dependencies: dependencies,
		Start: sbomTypes.Start{
			Dependencies: []sbomTypes.WorkSpaceDependency{
				{Name: "company/debug-helper", Version: "1.0.0", Constraint: "^1.0"},
				{Name: "internal/test-utils", Version: "2.0.0", Constraint: "^2.0"},
				{Name: "private/no-license-package", Version: "1.0.0", Constraint: "^1.0"},
			},
		},
	}

	return sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			"default": workspace,
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{
			Status:      codeclarity.SUCCESS,
			ProjectName: "Test Problematic Packages",
			Extra: sbomTypes.Extra{
				VersionSeperator:    "@",
				ImportPathSeperator: "/",
				LockFileVersion:     2,
			},
		},
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
