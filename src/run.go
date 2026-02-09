package vulnerabilities

// package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/conflictResolver"
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	extensionAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/extensionAnalyzer"
	frameworkAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/frameworkAnalyzer"
	outputGenerator "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	privatePackageAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/privatePackageAnalyzer"
	npmRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/npm"
	phpRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/php"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	vulnerabilitylookup "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityLookup"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/uptrace/bun"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
)

var sightingHTTPClient = &http.Client{Timeout: 10 * time.Second}

// declareSightings checks if a project URL is publicly accessible and, if so,
// reports vulnerability sightings to vulnerability-lookup.
func declareSightings(projectURL string, vulns []vulnerabilityFinder.Vulnerability) {
	resp, err := sightingHTTPClient.Get(projectURL)
	if err != nil {
		log.Printf("Failed to check project URL accessibility: %v", err)
		return
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode == 403 || strings.Contains(string(body), "Page not found") {
		return
	}
	for _, vuln := range vulns {
		vulnerabilitylookup.DeclareSighting(vuln, projectURL)
	}
}

// Start starts a vulnerability analysis on the given sbom
func Start(projectURL string, sbom sbomTypes.Output, languageId string, start time.Time, knowledge *bun.DB) vulnerabilityFinder.Output {
	if sbom.AnalysisInfo.Status != codeclarity.SUCCESS {
		exceptionManager.AddError("Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED, "Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
	}

	var vulnerabilityMatcher matcher.VulnerabilityMatcher

	switch languageId {
	case "JS":
		vulnerabilityMatcher = matcher.VulnerabilityMatcher{
			Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
			ConflictResolver:  conflictResolver.TrustOSVFirst,
			PackageRepository: npmRepository.NpmPackageRepository,
		}
	case "PHP":
		vulnerabilityMatcher = matcher.VulnerabilityMatcher{
			Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.PHP},
			ConflictResolver:  conflictResolver.TrustOSVFirst,
			PackageRepository: phpRepository.PhpPackageRepository,
		}
	default:
		exceptionManager.AddError("", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED, "", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
	}

	workspaces := map[string]vulnerabilityFinder.Workspace{}

	// Create deterministic ordering by sorting workspace keys
	workspaceKeys := make([]string, 0, len(sbom.WorkSpaces))
	for workspaceKey := range sbom.WorkSpaces {
		workspaceKeys = append(workspaceKeys, workspaceKey)
	}
	slices.Sort(workspaceKeys)

	for _, workspaceKey := range workspaceKeys {
		workspace := sbom.WorkSpaces[workspaceKey]
		vulns := vulnerabilityMatcher.GetWorkspaceVulnerabilities(workspace.Dependencies, knowledge)

		// For PHP projects, also analyze PHP extension vulnerabilities
		if languageId == "PHP" {
			analyzer := extensionAnalyzer.NewPHPExtensionAnalyzer()

			// Extract extensions from SBOM
			extensions := analyzer.ExtractExtensionsFromSBOM(sbom)

			// Filter to only relevant extensions for vulnerability tracking
			relevantExtensions := analyzer.FilterRelevantExtensions(extensions)

			// Analyze extension vulnerabilities
			extensionVulns := analyzer.AnalyzeExtensionVulnerabilities(relevantExtensions, knowledge)

			// Merge extension vulnerabilities with package vulnerabilities
			vulns = append(vulns, extensionVulns...)

			// Also analyze PHP framework-specific vulnerabilities with real database queries
			frameworkAnalyzer := frameworkAnalyzer.NewPHPFrameworkAnalyzer()

			// Extract framework information from SBOM
			frameworks := frameworkAnalyzer.ExtractFrameworkFromSBOM(sbom)

			// Analyze framework-specific vulnerabilities using real OSV/NVD/FriendsOfPHP queries
			frameworkVulns := frameworkAnalyzer.AnalyzeFrameworkVulnerabilities(frameworks, knowledge)

			// Merge framework vulnerabilities with existing vulnerabilities
			vulns = append(vulns, frameworkVulns...)
		}

		// Analyze private packages for vulnerabilities (for both JS and PHP)
		privateAnalyzer := privatePackageAnalyzer.NewPrivatePackageAnalyzer(knowledge)
		privateVulns := privateAnalyzer.AnalyzePrivatePackages(sbom, workspace.Dependencies)

		// Merge private package vulnerabilities with existing vulnerabilities
		vulns = append(vulns, privateVulns...)

		workspaces[workspaceKey] = vulnerabilityFinder.Workspace{
			Vulnerabilities: vulns,
		}

		user := os.Getenv("VULNERABILITY_LOOKUP_API_KEY")
		if user != "" && user != "!ChangeMe!" {
			declareSightings(projectURL, vulns)
		}
	}

	return outputGenerator.SuccessOutput(workspaces, sbom.AnalysisInfo, start)
}
