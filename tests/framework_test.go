package main

import (
	"testing"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	frameworkAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/frameworkAnalyzer"
	frameworkMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/frameworks"
)

func TestPHPFrameworkAnalyzer_ExtractFrameworkFromSBOM(t *testing.T) {
	analyzer := frameworkAnalyzer.NewPHPFrameworkAnalyzer()

	// Create test SBOM with Laravel framework
	testSBOM := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			"default": {
				Dependencies: map[string]map[string]sbomTypes.Versions{
					"laravel/framework": {
						"9.52.0": sbomTypes.Versions{
							Key: "9.52.0",
						},
					},
					"symfony/console": {
						"6.2.0": sbomTypes.Versions{
							Key: "6.2.0",
						},
					},
				},
			},
		},
	}

	frameworks := analyzer.ExtractFrameworkFromSBOM(testSBOM)

	if len(frameworks) == 0 {
		t.Fatal("Expected to detect at least one framework")
	}

	// Check Laravel detection
	var laravelFound bool
	for _, framework := range frameworks {
		if framework.Name == "Laravel" {
			laravelFound = true
			if framework.Version != "9.52.0" {
				t.Errorf("Expected Laravel version 9.52.0, got %s", framework.Version)
			}
			if framework.Type != "framework" {
				t.Errorf("Expected Laravel type 'framework', got %s", framework.Type)
			}
		}
	}

	if !laravelFound {
		t.Error("Laravel framework not detected")
	}
}

func TestPHPFrameworkAnalyzer_ExtractSymfonyComponents(t *testing.T) {
	analyzer := frameworkAnalyzer.NewPHPFrameworkAnalyzer()

	// Create test SBOM with Symfony components
	testSBOM := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			"default": {
				Dependencies: map[string]map[string]sbomTypes.Versions{
					"symfony/http-kernel": {
						"5.4.20": sbomTypes.Versions{
							Key: "5.4.20",
						},
					},
					"symfony/routing": {
						"5.4.20": sbomTypes.Versions{
							Key: "5.4.20",
						},
					},
				},
			},
		},
	}

	frameworks := analyzer.ExtractFrameworkFromSBOM(testSBOM)

	if len(frameworks) == 0 {
		t.Fatal("Expected to detect Symfony components")
	}

	var symfonyFound bool
	for _, framework := range frameworks {
		if framework.Name == "Symfony Components" {
			symfonyFound = true
			if framework.Type != "framework" {
				t.Errorf("Expected Symfony type 'framework', got %s", framework.Type)
			}
		}
	}

	if !symfonyFound {
		t.Error("Symfony components not detected")
	}
}

func TestPHPFrameworkAnalyzer_WordPressDetection(t *testing.T) {
	analyzer := frameworkAnalyzer.NewPHPFrameworkAnalyzer()

	// Create test SBOM with WordPress
	testSBOM := sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			"default": {
				Dependencies: map[string]map[string]sbomTypes.Versions{
					"johnpbloch/wordpress": {
						"6.2.0": sbomTypes.Versions{
							Key: "6.2.0",
						},
					},
				},
			},
		},
	}

	frameworks := analyzer.ExtractFrameworkFromSBOM(testSBOM)

	if len(frameworks) == 0 {
		t.Fatal("Expected to detect WordPress")
	}

	var wordpressFound bool
	for _, framework := range frameworks {
		if framework.Name == "WordPress" {
			wordpressFound = true
			if framework.Type != "cms" {
				t.Errorf("Expected WordPress type 'cms', got %s", framework.Type)
			}
		}
	}

	if !wordpressFound {
		t.Error("WordPress not detected")
	}
}

func TestPHPFrameworkAnalyzer_AnalyzeFrameworkVulnerabilities(t *testing.T) {
	analyzer := frameworkAnalyzer.NewPHPFrameworkAnalyzer()

	frameworks := []frameworkAnalyzer.FrameworkInfo{
		{
			Name:    "Laravel",
			Version: "8.50.0",
			Type:    "framework",
		},
		{
			Name:    "Symfony",
			Version: "5.4.15",
			Type:    "framework",
		},
	}

	// Test with nil knowledge DB (should handle gracefully)
	vulns := analyzer.AnalyzeFrameworkVulnerabilities(frameworks, nil)

	// Should return empty slice, not nil
	if vulns == nil {
		t.Error("Expected empty slice, got nil")
	}

	if len(vulns) != 0 {
		t.Errorf("Expected 0 vulnerabilities with nil DB, got %d", len(vulns))
	}
}

func TestPHPFrameworkMatcher_MatchFrameworkVulnerabilities(t *testing.T) {
	matcher := frameworkMatcher.PHPFrameworkVulnerabilityMatcher{}

	// Test with nil knowledge DB (should handle gracefully)
	matches, err := matcher.MatchFrameworkVulnerabilities("Laravel", "8.50.0", nil)

	if err == nil {
		t.Error("Expected error with nil knowledge DB")
	}

	if matches == nil {
		t.Error("Expected empty slice, got nil")
	}

	if len(matches) != 0 {
		t.Errorf("Expected 0 matches with nil DB, got %d", len(matches))
	}
}

func TestPHPFrameworkMatcher_BasicFunctionality(t *testing.T) {
	matcher := frameworkMatcher.PHPFrameworkVulnerabilityMatcher{}

	// Test that matcher can be created (basic instantiation check)
	_ = matcher // Use matcher to avoid unused variable warning

	// Test basic vulnerability matching function signature
	matches, err := matcher.MatchFrameworkVulnerabilities("TestFramework", "1.0.0", nil)

	// Should return error with nil DB
	if err == nil {
		t.Error("Expected error with nil knowledge database")
	}

	// Should return empty slice, not nil
	if matches == nil {
		t.Error("Expected empty slice, got nil")
	}
}
