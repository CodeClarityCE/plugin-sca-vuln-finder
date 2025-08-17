package frameworkAnalyzer

import (
	"fmt"
	"log"
	"strings"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	frameworkMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/frameworks"
	"github.com/uptrace/bun"
)

// PHPFrameworkAnalyzer analyzes PHP frameworks for vulnerabilities and security best practices
type PHPFrameworkAnalyzer struct {
	matcher frameworkMatcher.PHPFrameworkVulnerabilityMatcher
}

// NewPHPFrameworkAnalyzer creates a new PHP framework analyzer
func NewPHPFrameworkAnalyzer() *PHPFrameworkAnalyzer {
	return &PHPFrameworkAnalyzer{
		matcher: frameworkMatcher.PHPFrameworkVulnerabilityMatcher{},
	}
}

// FrameworkInfo represents detected framework information
type FrameworkInfo struct {
	Name    string
	Version string
	Type    string // "framework", "cms", "library"
}

// ExtractFrameworkFromSBOM extracts PHP framework information from the SBOM
func (analyzer *PHPFrameworkAnalyzer) ExtractFrameworkFromSBOM(sbom sbomTypes.Output) []FrameworkInfo {
	frameworks := []FrameworkInfo{}

	// Extract from metadata if available
	for workspaceKey, workspace := range sbom.WorkSpaces {
		log.Printf("Analyzing workspace %s for PHP frameworks", workspaceKey)

		// Check dependencies for framework packages
		for depName, depVersions := range workspace.Dependencies {
			if framework := analyzer.detectFrameworkFromDependency(depName, depVersions); framework != nil {
				frameworks = append(frameworks, *framework)
				log.Printf("Detected PHP framework: %s %s", framework.Name, framework.Version)
			}
		}
	}

	// Remove duplicates
	return analyzer.deduplicateFrameworks(frameworks)
}

// detectFrameworkFromDependency detects framework from dependency name and version
func (analyzer *PHPFrameworkAnalyzer) detectFrameworkFromDependency(depName string, depVersions map[string]sbomTypes.Versions) *FrameworkInfo {
	// Framework detection patterns
	frameworkPatterns := map[string]FrameworkInfo{
		"laravel/framework": {
			Name: "Laravel",
			Type: "framework",
		},
		"symfony/framework-bundle": {
			Name: "Symfony",
			Type: "framework",
		},
		"symfony/symfony": {
			Name: "Symfony",
			Type: "framework",
		},
		"johnpbloch/wordpress": {
			Name: "WordPress",
			Type: "cms",
		},
		"drupal/core": {
			Name: "Drupal",
			Type: "cms",
		},
		"cakephp/cakephp": {
			Name: "CakePHP",
			Type: "framework",
		},
		"codeigniter4/framework": {
			Name: "CodeIgniter",
			Type: "framework",
		},
		"slim/slim": {
			Name: "Slim",
			Type: "framework",
		},
		"yiisoft/yii2": {
			Name: "Yii2",
			Type: "framework",
		},
		"laravel/lumen-framework": {
			Name: "Lumen",
			Type: "framework",
		},
		"laminas/laminas-mvc": {
			Name: "Laminas",
			Type: "framework",
		},
		"zendframework/zend-mvc": {
			Name: "Zend Framework",
			Type: "framework",
		},
	}

	// Check for exact match
	if framework, exists := frameworkPatterns[depName]; exists {
		// Get version from dependency
		version := analyzer.extractVersionFromDependency(depVersions)
		framework.Version = version
		return &framework
	}

	// Check for Symfony components pattern
	if strings.HasPrefix(depName, "symfony/") && depName != "symfony/polyfill-mbstring" && depName != "symfony/polyfill-php80" {
		version := analyzer.extractVersionFromDependency(depVersions)
		return &FrameworkInfo{
			Name:    "Symfony Components",
			Version: version,
			Type:    "framework",
		}
	}

	return nil
}

// extractVersionFromDependency extracts version string from dependency versions map
func (analyzer *PHPFrameworkAnalyzer) extractVersionFromDependency(depVersions map[string]sbomTypes.Versions) string {
	// Try to get the most specific version
	for versionStr := range depVersions {
		if versionStr != "" && versionStr != "*" {
			return versionStr
		}
	}
	return "unknown"
}

// deduplicateFrameworks removes duplicate framework entries
func (analyzer *PHPFrameworkAnalyzer) deduplicateFrameworks(frameworks []FrameworkInfo) []FrameworkInfo {
	seen := make(map[string]bool)
	result := []FrameworkInfo{}

	for _, framework := range frameworks {
		key := fmt.Sprintf("%s-%s", framework.Name, framework.Version)
		if !seen[key] {
			seen[key] = true
			result = append(result, framework)
		}
	}

	return result
}

// AnalyzeFrameworkVulnerabilities analyzes frameworks for vulnerabilities and security issues
func (analyzer *PHPFrameworkAnalyzer) AnalyzeFrameworkVulnerabilities(
	frameworks []FrameworkInfo,
	knowledge *bun.DB,
) []vulnerabilityFinder.Vulnerability {

	// Initialize empty slice instead of nil
	vulnerabilities := make([]vulnerabilityFinder.Vulnerability, 0)

	// Handle nil knowledge DB gracefully
	if knowledge == nil {
		log.Printf("Knowledge database not available, skipping framework vulnerability analysis")
		return vulnerabilities
	}

	for _, framework := range frameworks {
		log.Printf("Analyzing vulnerabilities for PHP framework: %s %s", framework.Name, framework.Version)

		// Match vulnerabilities for this framework
		matches, err := analyzer.matcher.MatchFrameworkVulnerabilities(framework.Name, framework.Version, knowledge)
		if err != nil {
			log.Printf("Error analyzing vulnerabilities for framework %s: %v", framework.Name, err)
			continue
		}

		// Convert matches to vulnerability objects
		for _, match := range matches {
			vuln := vulnerabilityFinder.Vulnerability{
				VulnerabilityId:    match.VulnerabilityID,
				PackageName:        match.PackageName,
				Constraint:         match.PackageVersion,
				CurrentVersion:     match.PackageVersion,
				DirectDependency:   true, // Framework dependencies are typically direct
				Source:             match.Source,
				CVSS:               match.CVSS,
				Summary:            match.Summary,
				Details:            match.Details,
				References:         match.References,
				PublishedDate:      match.PublishedDate,
				ModifiedDate:       match.ModifiedDate,
				WithdrawnDate:      match.WithdrawnDate,
				ExtensionType:      "php-framework",                             // Mark as PHP framework vulnerability
				AffectedDependency: fmt.Sprintf("framework-%s", framework.Name), // Use existing field
				AffectedVersion:    framework.Version,                           // Use existing field
			}

			// Add framework-specific severity adjustments
			vuln = analyzer.adjustFrameworkSeverity(vuln, framework)

			vulnerabilities = append(vulnerabilities, vuln)
		}

		// Add framework-specific security rules
		frameworkRules := analyzer.getFrameworkSecurityRules(framework)
		vulnerabilities = append(vulnerabilities, frameworkRules...)
	}

	log.Printf("Found %d vulnerabilities and security issues in PHP frameworks", len(vulnerabilities))
	return vulnerabilities
}

// adjustFrameworkSeverity adjusts vulnerability severity based on framework context
func (analyzer *PHPFrameworkAnalyzer) adjustFrameworkSeverity(vuln vulnerabilityFinder.Vulnerability, framework FrameworkInfo) vulnerabilityFinder.Vulnerability {
	// Increase severity for certain framework types or versions
	switch framework.Name {
	case "WordPress":
		// WordPress vulnerabilities are often critical due to widespread usage
		if vuln.CVSS < 7.0 && vuln.CVSS > 0 {
			vuln.CVSS = vuln.CVSS + 1.0 // Bump severity slightly
			vuln.Details = fmt.Sprintf("[WordPress Context] %s", vuln.Details)
		}
	case "Laravel":
		// Laravel framework vulnerabilities can be critical in production
		if strings.Contains(vuln.Summary, "authentication") || strings.Contains(vuln.Summary, "authorization") {
			vuln.Details = fmt.Sprintf("[Laravel Security] %s", vuln.Details)
		}
	case "Symfony":
		// Symfony security vulnerabilities are often well-documented
		if strings.Contains(vuln.Summary, "security") {
			vuln.Details = fmt.Sprintf("[Symfony Security Advisory] %s", vuln.Details)
		}
	}

	return vuln
}

// getFrameworkSecurityRules returns framework-specific security rules and best practices
func (analyzer *PHPFrameworkAnalyzer) getFrameworkSecurityRules(framework FrameworkInfo) []vulnerabilityFinder.Vulnerability {
	rules := []vulnerabilityFinder.Vulnerability{}

	switch framework.Name {
	case "Laravel":
		rules = append(rules, analyzer.getLaravelSecurityRules(framework)...)
	case "Symfony":
		rules = append(rules, analyzer.getSymfonySecurityRules(framework)...)
	case "WordPress":
		rules = append(rules, analyzer.getWordPressSecurityRules(framework)...)
	case "Drupal":
		rules = append(rules, analyzer.getDrupalSecurityRules(framework)...)
	case "CakePHP":
		rules = append(rules, analyzer.getCakePHPSecurityRules(framework)...)
	}

	return rules
}

// getLaravelSecurityRules returns Laravel-specific security rules
func (analyzer *PHPFrameworkAnalyzer) getLaravelSecurityRules(framework FrameworkInfo) []vulnerabilityFinder.Vulnerability {
	rules := []vulnerabilityFinder.Vulnerability{}

	// Laravel version-specific rules
	if analyzer.isVersionAffected(framework.Version, "<8.0.0") {
		rules = append(rules, vulnerabilityFinder.Vulnerability{
			VulnerabilityId:    "LARAVEL-SEC-001",
			AffectedDependency: fmt.Sprintf("framework-%s", framework.Name),
			AffectedVersion:    framework.Version,
			Summary:            "Laravel < 8.0 has known security vulnerabilities",
			Details:            "Laravel versions before 8.0 contain multiple security vulnerabilities. Consider upgrading to Laravel 8.x or higher.",
			CVSS:               6.5,
			Source:             "Framework Security Analysis",
			ExtensionType:      "php-framework-rule",
			References:         []string{"https://laravel.com/docs/8.x/releases"},
		})
	}

	if analyzer.isVersionAffected(framework.Version, "<9.0.0") {
		rules = append(rules, vulnerabilityFinder.Vulnerability{
			VulnerabilityId:    "LARAVEL-SEC-002",
			AffectedDependency: fmt.Sprintf("framework-%s", framework.Name),
			AffectedVersion:    framework.Version,
			Summary:            "Laravel debug mode security risk",
			Details:            "Ensure APP_DEBUG is set to false in production environments to prevent information disclosure.",
			CVSS:               4.0,
			Source:             "Framework Security Analysis",
			ExtensionType:      "php-framework-rule",
			References:         []string{"https://laravel.com/docs/configuration#debug-mode"},
		})
	}

	return rules
}

// getSymfonySecurityRules returns Symfony-specific security rules
func (analyzer *PHPFrameworkAnalyzer) getSymfonySecurityRules(framework FrameworkInfo) []vulnerabilityFinder.Vulnerability {
	rules := []vulnerabilityFinder.Vulnerability{}

	if analyzer.isVersionAffected(framework.Version, "<5.4.0") {
		rules = append(rules, vulnerabilityFinder.Vulnerability{
			VulnerabilityId:    "SYMFONY-SEC-001",
			AffectedDependency: fmt.Sprintf("framework-%s", framework.Name),
			AffectedVersion:    framework.Version,
			Summary:            "Symfony < 5.4 LTS recommended for security",
			Details:            "Consider upgrading to Symfony 5.4 LTS or 6.x for latest security patches and long-term support.",
			CVSS:               5.0,
			Source:             "Framework Security Analysis",
			ExtensionType:      "php-framework-rule",
			References:         []string{"https://symfony.com/releases"},
		})
	}

	return rules
}

// getWordPressSecurityRules returns WordPress-specific security rules
func (analyzer *PHPFrameworkAnalyzer) getWordPressSecurityRules(framework FrameworkInfo) []vulnerabilityFinder.Vulnerability {
	rules := []vulnerabilityFinder.Vulnerability{}

	rules = append(rules, vulnerabilityFinder.Vulnerability{
		VulnerabilityId:    "WORDPRESS-SEC-001",
		AffectedDependency: fmt.Sprintf("framework-%s", framework.Name),
		AffectedVersion:    framework.Version,
		Summary:            "WordPress requires regular security updates",
		Details:            "WordPress should be kept up-to-date with the latest security patches. Enable automatic updates for security releases.",
		CVSS:               7.0,
		Source:             "Framework Security Analysis",
		ExtensionType:      "php-framework-rule",
		References:         []string{"https://wordpress.org/support/article/updating-wordpress/"},
	})

	return rules
}

// getDrupalSecurityRules returns Drupal-specific security rules
func (analyzer *PHPFrameworkAnalyzer) getDrupalSecurityRules(framework FrameworkInfo) []vulnerabilityFinder.Vulnerability {
	rules := []vulnerabilityFinder.Vulnerability{}

	if analyzer.isVersionAffected(framework.Version, "<9.0.0") {
		rules = append(rules, vulnerabilityFinder.Vulnerability{
			VulnerabilityId:    "DRUPAL-SEC-001",
			AffectedDependency: fmt.Sprintf("framework-%s", framework.Name),
			AffectedVersion:    framework.Version,
			Summary:            "Drupal < 9 end of life security risk",
			Details:            "Drupal 8 and earlier versions are end-of-life and no longer receive security updates. Upgrade to Drupal 9 or 10.",
			CVSS:               8.0,
			Source:             "Framework Security Analysis",
			ExtensionType:      "php-framework-rule",
			References:         []string{"https://www.drupal.org/psa-2021-06-29"},
		})
	}

	return rules
}

// getCakePHPSecurityRules returns CakePHP-specific security rules
func (analyzer *PHPFrameworkAnalyzer) getCakePHPSecurityRules(framework FrameworkInfo) []vulnerabilityFinder.Vulnerability {
	rules := []vulnerabilityFinder.Vulnerability{}

	if analyzer.isVersionAffected(framework.Version, "<4.0.0") {
		rules = append(rules, vulnerabilityFinder.Vulnerability{
			VulnerabilityId:    "CAKEPHP-SEC-001",
			AffectedDependency: fmt.Sprintf("framework-%s", framework.Name),
			AffectedVersion:    framework.Version,
			Summary:            "CakePHP 4.x recommended for security",
			Details:            "CakePHP 4.x includes important security improvements and should be used for new projects.",
			CVSS:               5.5,
			Source:             "Framework Security Analysis",
			ExtensionType:      "php-framework-rule",
			References:         []string{"https://book.cakephp.org/4/en/appendices/4-0-migration-guide.html"},
		})
	}

	return rules
}

// isVersionAffected checks if a version matches a constraint (simplified version comparison)
func (analyzer *PHPFrameworkAnalyzer) isVersionAffected(version, constraint string) bool {
	// Simplified version comparison - in production this should use proper semver
	if version == "unknown" || version == "" {
		return true // Assume affected if version is unknown
	}

	// Basic constraint parsing for demonstration
	if strings.HasPrefix(constraint, "<") {
		constraintVersion := strings.TrimPrefix(constraint, "<")
		// Simple string comparison (this should be replaced with proper semver comparison)
		return version < constraintVersion
	}

	return false
}
