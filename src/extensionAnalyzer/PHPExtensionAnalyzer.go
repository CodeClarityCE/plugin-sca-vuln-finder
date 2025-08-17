package extensionAnalyzer

import (
	"fmt"
	"log"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	extensionMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/extensions"
	"github.com/uptrace/bun"
)

// PHPExtensionAnalyzer analyzes PHP extensions for vulnerabilities
type PHPExtensionAnalyzer struct {
	matcher extensionMatcher.PHPExtensionVulnerabilityMatcher
}

// NewPHPExtensionAnalyzer creates a new PHP extension analyzer
func NewPHPExtensionAnalyzer() *PHPExtensionAnalyzer {
	return &PHPExtensionAnalyzer{
		matcher: extensionMatcher.PHPExtensionVulnerabilityMatcher{},
	}
}

// ExtractExtensionsFromSBOM extracts PHP extension information from the SBOM
func (analyzer *PHPExtensionAnalyzer) ExtractExtensionsFromSBOM(sbom sbomTypes.Output) map[string]string {
	// For now, return a placeholder set of common PHP extensions
	// TODO: Extract from SBOM extra field when PHP SBOM is properly integrated
	log.Printf("Note: Using placeholder PHP extensions for vulnerability analysis")

	// Placeholder common PHP extensions that might be present
	placeholderExtensions := map[string]string{
		"curl":     "7.68.0",
		"json":     "1.6.0",
		"openssl":  "1.1.1",
		"mbstring": "7.4.0",
		"xml":      "7.4.0",
		"mysqli":   "7.4.0",
		"pdo":      "7.4.0",
		"zip":      "1.15.0",
		"gd":       "2.1.0",
	}

	return placeholderExtensions
}

// AnalyzeExtensionVulnerabilities analyzes extensions for vulnerabilities
func (analyzer *PHPExtensionAnalyzer) AnalyzeExtensionVulnerabilities(
	extensions map[string]string,
	knowledge *bun.DB,
) []vulnerabilityFinder.Vulnerability {

	// Initialize empty slice instead of nil
	vulnerabilities := make([]vulnerabilityFinder.Vulnerability, 0)

	// Handle nil knowledge DB gracefully
	if knowledge == nil {
		log.Printf("Knowledge database not available, skipping extension vulnerability analysis")
		return vulnerabilities
	}

	for extensionName, extensionVersion := range extensions {
		log.Printf("Analyzing vulnerabilities for PHP extension: %s (version: %s)", extensionName, extensionVersion)

		// Match vulnerabilities for this extension
		matches, err := analyzer.matcher.MatchExtensionVulnerabilities(extensionName, extensionVersion, knowledge)
		if err != nil {
			log.Printf("Error analyzing vulnerabilities for extension %s: %v", extensionName, err)
			continue
		}

		// Convert matches to vulnerability objects
		for _, match := range matches {
			vuln := vulnerabilityFinder.Vulnerability{
				VulnerabilityId:    match.VulnerabilityID,
				PackageName:        match.PackageName,
				Constraint:         match.PackageVersion, // For extensions, constraint is the specific version
				CurrentVersion:     match.PackageVersion,
				DirectDependency:   false, // Extensions are not direct dependencies in the traditional sense
				Source:             match.Source,
				CVSS:               match.CVSS,
				Summary:            match.Summary,
				Details:            match.Details,
				References:         match.References,
				PublishedDate:      match.PublishedDate,
				ModifiedDate:       match.ModifiedDate,
				WithdrawnDate:      match.WithdrawnDate,
				ExtensionType:      "php-extension",                      // Mark as PHP extension vulnerability
				AffectedDependency: fmt.Sprintf("ext-%s", extensionName), // Use existing field
				AffectedVersion:    extensionVersion,                     // Use existing field
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	log.Printf("Found %d vulnerabilities in PHP extensions", len(vulnerabilities))
	return vulnerabilities
}

// FilterRelevantExtensions filters extensions that are relevant for vulnerability tracking
func (analyzer *PHPExtensionAnalyzer) FilterRelevantExtensions(extensions map[string]string) map[string]string {
	relevant := make(map[string]string)

	// Extensions that are commonly vulnerable and should be tracked
	vulnerableExtensions := map[string]bool{
		"curl":       true,
		"openssl":    true,
		"gd":         true,
		"xml":        true,
		"libxml":     true,
		"zip":        true,
		"mysqli":     true,
		"pdo":        true,
		"soap":       true,
		"ftp":        true,
		"iconv":      true,
		"mbstring":   true,
		"fileinfo":   true,
		"exif":       true,
		"filter":     true,
		"hash":       true,
		"intl":       true,
		"json":       true,
		"session":    true,
		"sqlite3":    true,
		"xmlreader":  true,
		"xmlwriter":  true,
		"simplexml":  true,
		"dom":        true,
		"pcre":       true,
		"spl":        true,
		"reflection": true,
		"date":       true,
		"standard":   true,
	}

	for name, version := range extensions {
		if vulnerableExtensions[name] {
			relevant[name] = version
		}
	}

	return relevant
}
