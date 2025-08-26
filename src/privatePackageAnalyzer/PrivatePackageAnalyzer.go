package privatePackageAnalyzer

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilityFinderTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/uptrace/bun"
)

// PrivateRepositoryInfo represents private repository metadata from SBOM
type PrivateRepositoryInfo struct {
	PrivatePackagesCount    int                 `json:"private_packages_count"`
	PrivateRepositories     int                 `json:"private_repositories"`
	AuthenticationSummary   map[string]int      `json:"authentication_summary"`
	ResolutionErrorSummary  map[string]int      `json:"resolution_error_summary"`
	PrivateRepositoriesList []PrivateRepository `json:"private_repositories_list"`
}

// PrivateRepository represents a private repository configuration
type PrivateRepository struct {
	Type    string                 `json:"type"`
	URL     string                 `json:"url"`
	Options map[string]interface{} `json:"options,omitempty"`
	Only    []string               `json:"only,omitempty"`
	Exclude []string               `json:"exclude,omitempty"`
}

// PrivatePackageAnalyzer analyzes vulnerabilities in private packages
type PrivatePackageAnalyzer struct {
	knowledge *bun.DB
}

// NewPrivatePackageAnalyzer creates a new private package analyzer
func NewPrivatePackageAnalyzer(knowledge *bun.DB) *PrivatePackageAnalyzer {
	return &PrivatePackageAnalyzer{
		knowledge: knowledge,
	}
}

// AnalyzePrivatePackages identifies and analyzes private packages from SBOM
func (ppa *PrivatePackageAnalyzer) AnalyzePrivatePackages(sbom sbomTypes.Output, dependencies map[string]map[string]sbomTypes.Versions) []vulnerabilityFinderTypes.Vulnerability {
	vulnerabilities := []vulnerabilityFinderTypes.Vulnerability{}

	// Extract private repository information from SBOM
	privateRepoInfo := ppa.extractPrivateRepositoryInfo(sbom)
	if privateRepoInfo == nil {
		log.Println("No private repository information found in SBOM")
		return vulnerabilities
	}

	log.Printf("Found %d private packages in %d private repositories",
		privateRepoInfo.PrivatePackagesCount, privateRepoInfo.PrivateRepositories)

	// Identify private packages
	privatePackages := ppa.identifyPrivatePackages(dependencies, privateRepoInfo)

	// Analyze each private package for potential vulnerabilities
	for packageName, versions := range privatePackages {
		for version, versionInfo := range versions {
			// Analyze private package vulnerabilities
			packageVulns := ppa.analyzePrivatePackageVulnerabilities(packageName, version, versionInfo, privateRepoInfo)
			vulnerabilities = append(vulnerabilities, packageVulns...)
		}
	}

	log.Printf("Found %d potential vulnerabilities in private packages", len(vulnerabilities))
	return vulnerabilities
}

// extractPrivateRepositoryInfo extracts private repository metadata from SBOM
func (ppa *PrivatePackageAnalyzer) extractPrivateRepositoryInfo(sbom sbomTypes.Output) *PrivateRepositoryInfo {
	// The SBOM Extra field structure varies between JS and PHP SBOMs
	// We need to use reflection or type assertion to handle both types

	// Try to convert the Extra field to a map for PHP SBOMs
	extraData, err := json.Marshal(sbom.AnalysisInfo.Extra)
	if err != nil {
		log.Printf("Failed to marshal SBOM extra data: %v", err)
		return nil
	}

	var extraMap map[string]interface{}
	if err := json.Unmarshal(extraData, &extraMap); err != nil {
		log.Printf("Failed to unmarshal SBOM extra data: %v", err)
		return nil
	}

	privateRepoData, exists := extraMap["private_repository_info"]
	if !exists {
		// No private repository information found
		return nil
	}

	// Convert to our struct
	jsonData, err := json.Marshal(privateRepoData)
	if err != nil {
		log.Printf("Failed to marshal private repository info: %v", err)
		return nil
	}

	var privateRepoInfo PrivateRepositoryInfo
	if err := json.Unmarshal(jsonData, &privateRepoInfo); err != nil {
		log.Printf("Failed to unmarshal private repository info: %v", err)
		return nil
	}

	return &privateRepoInfo
}

// identifyPrivatePackages identifies which packages come from private repositories
func (ppa *PrivatePackageAnalyzer) identifyPrivatePackages(dependencies map[string]map[string]sbomTypes.Versions, privateRepoInfo *PrivateRepositoryInfo) map[string]map[string]sbomTypes.Versions {
	privatePackages := make(map[string]map[string]sbomTypes.Versions)

	for packageName, versions := range dependencies {
		for version, versionInfo := range versions {
			if ppa.isPrivatePackage(packageName, versionInfo, privateRepoInfo) {
				if privatePackages[packageName] == nil {
					privatePackages[packageName] = make(map[string]sbomTypes.Versions)
				}
				privatePackages[packageName][version] = versionInfo
			}
		}
	}

	return privatePackages
}

// isPrivatePackage determines if a package is from a private repository
func (ppa *PrivatePackageAnalyzer) isPrivatePackage(packageName string, versionInfo sbomTypes.Versions, privateRepoInfo *PrivateRepositoryInfo) bool {
	// Check if package matches private repository patterns
	for _, repo := range privateRepoInfo.PrivateRepositoriesList {
		// Check "only" filters - if package matches, it's private
		if len(repo.Only) > 0 {
			for _, pattern := range repo.Only {
				if ppa.matchesPattern(packageName, pattern) {
					return true
				}
			}
			continue // If "only" is defined but no match, skip this repo
		}

		// Check "exclude" filters - if package matches, it's NOT from this private repo
		excluded := false
		for _, pattern := range repo.Exclude {
			if ppa.matchesPattern(packageName, pattern) {
				excluded = true
				break
			}
		}

		// If not excluded and it's a private repository, consider it private
		if !excluded && ppa.isPrivateRepositoryURL(repo.URL) {
			return true
		}
	}

	// Additional heuristics for private packages
	return ppa.hasPrivatePackageIndicators(packageName, versionInfo)
}

// matchesPattern checks if package name matches a pattern (supports wildcards)
func (ppa *PrivatePackageAnalyzer) matchesPattern(packageName, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if strings.Contains(pattern, "*") {
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			return strings.HasPrefix(packageName, prefix)
		}
		if strings.HasPrefix(pattern, "*") {
			suffix := strings.TrimPrefix(pattern, "*")
			return strings.HasSuffix(packageName, suffix)
		}
		// Middle wildcard - simple implementation
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(packageName, parts[0]) && strings.HasSuffix(packageName, parts[1])
		}
	}

	return packageName == pattern
}

// isPrivateRepositoryURL checks if a URL indicates a private repository
func (ppa *PrivatePackageAnalyzer) isPrivateRepositoryURL(url string) bool {
	url = strings.ToLower(url)

	// Common private repository indicators
	privateIndicators := []string{
		"repo.company.com",
		"packages.company.com",
		"gitlab.company.com",
		"github.company.com",
		".internal",
		"packagist.com", // Private Packagist instances
		"repo.packagist.com",
	}

	for _, indicator := range privateIndicators {
		if strings.Contains(url, indicator) {
			return true
		}
	}

	// If URL contains "repo" or "private" it's likely private
	if strings.Contains(url, "repo") || strings.Contains(url, "private") {
		return true
	}

	return false
}

// hasPrivatePackageIndicators checks for private package naming patterns
func (ppa *PrivatePackageAnalyzer) hasPrivatePackageIndicators(packageName string, versionInfo sbomTypes.Versions) bool {
	packageName = strings.ToLower(packageName)

	// Common private package naming patterns
	privatePatterns := []string{
		"company/",
		"acme/",
		"internal/",
		"private/",
		"enterprise/",
		"corp/",
	}

	for _, pattern := range privatePatterns {
		if strings.HasPrefix(packageName, pattern) {
			return true
		}
	}

	// Check licenses for proprietary indicators
	for _, license := range versionInfo.Licenses {
		license = strings.ToLower(license)
		if strings.Contains(license, "proprietary") ||
			strings.Contains(license, "confidential") ||
			strings.Contains(license, "internal") {
			return true
		}
	}

	return false
}

// analyzePrivatePackageVulnerabilities analyzes vulnerabilities for a specific private package
func (ppa *PrivatePackageAnalyzer) analyzePrivatePackageVulnerabilities(packageName, version string, versionInfo sbomTypes.Versions, privateRepoInfo *PrivateRepositoryInfo) []vulnerabilityFinderTypes.Vulnerability {
	vulnerabilities := []vulnerabilityFinderTypes.Vulnerability{}

	// 1. Check for known vulnerability patterns in private packages
	patternVulns := ppa.analyzePrivatePackagePatterns(packageName, version, versionInfo)
	vulnerabilities = append(vulnerabilities, patternVulns...)

	// 2. Check for license compliance issues
	licenseVulns := ppa.analyzeLicenseCompliance(packageName, version, versionInfo)
	vulnerabilities = append(vulnerabilities, licenseVulns...)

	// 3. Check for security policy violations
	policyVulns := ppa.analyzeSecurityPolicyViolations(packageName, version, versionInfo, privateRepoInfo)
	vulnerabilities = append(vulnerabilities, policyVulns...)

	// 4. Check dependencies of private packages for known vulnerabilities
	dependencyVulns := ppa.analyzePrivatePackageDependencies(packageName, version, versionInfo)
	vulnerabilities = append(vulnerabilities, dependencyVulns...)

	return vulnerabilities
}

// analyzePrivatePackagePatterns checks for known vulnerability patterns
func (ppa *PrivatePackageAnalyzer) analyzePrivatePackagePatterns(packageName, version string, versionInfo sbomTypes.Versions) []vulnerabilityFinderTypes.Vulnerability {
	vulnerabilities := []vulnerabilityFinderTypes.Vulnerability{}

	// Check for packages with known problematic patterns
	problematicPatterns := []struct {
		pattern     string
		description string
		severity    string
		cwe         string
	}{
		{
			pattern:     "debug",
			description: "Debug package in production - potential information disclosure",
			severity:    "MEDIUM",
			cwe:         "CWE-200",
		},
		{
			pattern:     "test",
			description: "Test package in production - potential security risk",
			severity:    "LOW",
			cwe:         "CWE-489",
		},
		{
			pattern:     "internal-auth",
			description: "Internal authentication package - requires security review",
			severity:    "HIGH",
			cwe:         "CWE-287",
		},
		{
			pattern:     "legacy",
			description: "Legacy package - may contain outdated security practices",
			severity:    "MEDIUM",
			cwe:         "CWE-1104",
		},
	}

	packageNameLower := strings.ToLower(packageName)
	for _, pattern := range problematicPatterns {
		if strings.Contains(packageNameLower, pattern.pattern) {
			vuln := vulnerabilityFinderTypes.Vulnerability{
				VulnerabilityId:    fmt.Sprintf("PRIVATE-PATTERN-%s-%s", strings.ToUpper(pattern.pattern), packageName),
				AffectedDependency: packageName,
				AffectedVersion:    version,
				Severity:           ppa.createSeverity(pattern.severity),
				Sources:            []vulnerabilityFinderTypes.VulnerabilitySource{vulnerabilityFinderTypes.PRIVATE_ANALYSIS},
				Weaknesses: []vulnerabilityFinderTypes.VulnerabilityMatchWeakness{
					{
						WeaknessId: pattern.cwe,
					},
				},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	return vulnerabilities
}

// analyzeLicenseCompliance checks for license compliance issues
func (ppa *PrivatePackageAnalyzer) analyzeLicenseCompliance(packageName, version string, versionInfo sbomTypes.Versions) []vulnerabilityFinderTypes.Vulnerability {
	vulnerabilities := []vulnerabilityFinderTypes.Vulnerability{}

	// Check for missing or problematic licenses
	if len(versionInfo.Licenses) == 0 {
		vuln := vulnerabilityFinderTypes.Vulnerability{
			VulnerabilityId:    fmt.Sprintf("PRIVATE-LICENSE-MISSING-%s", packageName),
			AffectedDependency: packageName,
			AffectedVersion:    version,
			Severity:           ppa.createSeverity("MEDIUM"),
			Sources:            []vulnerabilityFinderTypes.VulnerabilitySource{vulnerabilityFinderTypes.PRIVATE_ANALYSIS},
			Weaknesses: []vulnerabilityFinderTypes.VulnerabilityMatchWeakness{
				{
					WeaknessId: "CWE-1104", // Use of Unmaintained Third Party Components
				},
			},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Check for restrictive licenses that might cause legal issues
	restrictiveLicenses := []string{"GPL-3.0", "AGPL-3.0", "SSPL"}
	for _, license := range versionInfo.Licenses {
		for _, restrictive := range restrictiveLicenses {
			if strings.Contains(strings.ToUpper(license), restrictive) {
				vuln := vulnerabilityFinderTypes.Vulnerability{
					VulnerabilityId:    fmt.Sprintf("PRIVATE-LICENSE-RESTRICTIVE-%s-%s", restrictive, packageName),
					AffectedDependency: packageName,
					AffectedVersion:    version,
					Severity:           ppa.createSeverity("LOW"),
					Sources:            []vulnerabilityFinderTypes.VulnerabilitySource{vulnerabilityFinderTypes.PRIVATE_ANALYSIS},
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

// analyzeSecurityPolicyViolations checks for security policy violations
func (ppa *PrivatePackageAnalyzer) analyzeSecurityPolicyViolations(packageName, version string, versionInfo sbomTypes.Versions, privateRepoInfo *PrivateRepositoryInfo) []vulnerabilityFinderTypes.Vulnerability {
	vulnerabilities := []vulnerabilityFinderTypes.Vulnerability{}

	// Check if package comes from untrusted private repositories
	if len(privateRepoInfo.ResolutionErrorSummary) > 0 {
		if authFailures, exists := privateRepoInfo.ResolutionErrorSummary["auth_failures"]; exists && authFailures > 0 {
			vuln := vulnerabilityFinderTypes.Vulnerability{
				VulnerabilityId:    fmt.Sprintf("PRIVATE-AUTH-FAILURE-%s", packageName),
				AffectedDependency: packageName,
				AffectedVersion:    version,
				Severity:           ppa.createSeverity("HIGH"),
				Sources:            []vulnerabilityFinderTypes.VulnerabilitySource{vulnerabilityFinderTypes.PRIVATE_ANALYSIS},
				Weaknesses: []vulnerabilityFinderTypes.VulnerabilityMatchWeakness{
					{
						WeaknessId: "CWE-287", // Improper Authentication
					},
				},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}

	// Check for packages that might violate naming conventions
	if strings.Contains(packageName, "test") && versionInfo.Prod {
		vuln := vulnerabilityFinderTypes.Vulnerability{
			VulnerabilityId:    fmt.Sprintf("PRIVATE-POLICY-TEST-IN-PROD-%s", packageName),
			AffectedDependency: packageName,
			AffectedVersion:    version,
			Severity:           ppa.createSeverity("MEDIUM"),
			Sources:            []vulnerabilityFinderTypes.VulnerabilitySource{vulnerabilityFinderTypes.PRIVATE_ANALYSIS},
			Weaknesses: []vulnerabilityFinderTypes.VulnerabilityMatchWeakness{
				{
					WeaknessId: "CWE-489", // Active Debug Code
				},
			},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// analyzePrivatePackageDependencies analyzes dependencies of private packages
func (ppa *PrivatePackageAnalyzer) analyzePrivatePackageDependencies(packageName, version string, versionInfo sbomTypes.Versions) []vulnerabilityFinderTypes.Vulnerability {
	vulnerabilities := []vulnerabilityFinderTypes.Vulnerability{}

	// Check if private package has too many dependencies (supply chain risk)
	dependencyCount := len(versionInfo.Dependencies) + len(versionInfo.Requires)
	if dependencyCount > 50 {
		vuln := vulnerabilityFinderTypes.Vulnerability{
			VulnerabilityId:    fmt.Sprintf("PRIVATE-SUPPLY-CHAIN-RISK-%s", packageName),
			AffectedDependency: packageName,
			AffectedVersion:    version,
			Severity:           ppa.createSeverity("LOW"),
			Sources:            []vulnerabilityFinderTypes.VulnerabilitySource{vulnerabilityFinderTypes.PRIVATE_ANALYSIS},
			Weaknesses: []vulnerabilityFinderTypes.VulnerabilityMatchWeakness{
				{
					WeaknessId: "CWE-1104", // Use of Unmaintained Third Party Components
				},
			},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Note: We could also check if private package dependencies have known vulnerabilities
	// This would require cross-referencing with the main vulnerability database

	return vulnerabilities
}

// createSeverity creates a VulnerabilityMatchSeverity struct for private analysis
func (ppa *PrivatePackageAnalyzer) createSeverity(severityLevel string) vulnerabilityFinderTypes.VulnerabilityMatchSeverity {
	var severityClass vulnerabilityFinderTypes.CVSS_CLASSV3
	var severityScore float64

	switch strings.ToUpper(severityLevel) {
	case "CRITICAL":
		severityClass = vulnerabilityFinderTypes.CRITICAL
		severityScore = 9.0
	case "HIGH":
		severityClass = vulnerabilityFinderTypes.HIGH
		severityScore = 7.5
	case "MEDIUM":
		severityClass = vulnerabilityFinderTypes.MEDIUM
		severityScore = 5.0
	case "LOW":
		severityClass = vulnerabilityFinderTypes.LOW
		severityScore = 2.5
	default:
		severityClass = vulnerabilityFinderTypes.LOW
		severityScore = 2.0
	}

	return vulnerabilityFinderTypes.VulnerabilityMatchSeverity{
		SeverityClass: severityClass,
		Severity:      severityScore,
		SeverityType:  vulnerabilityFinderTypes.CVSS_V3,
		Vector:        fmt.Sprintf("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"),
	}
}
