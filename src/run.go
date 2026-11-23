package vulnerabilities

// package main

import (
	"context"
	"fmt"
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
	outputGenerator "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	privatePackageAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/privatePackageAnalyzer"
	npmRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/npm"
	phpRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/php"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	vulnerabilitylookup "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityLookup"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	knowledgeTypes "github.com/CodeClarityCE/utility-types/knowledge_db"
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
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode == 403 || strings.Contains(string(body), "Page not found") {
		return
	}
	for _, vuln := range vulns {
		vulnerabilitylookup.DeclareSighting(vuln, projectURL)
	}
}

// Start starts a vulnerability analysis on the given sbom. knowledgeAsOf, when
// non-nil, drops OSV advisories published after that day (the whole day stays
// in range) before matching.
func Start(projectURL string, sbom sbomTypes.Output, languageId string, start time.Time, knowledge *bun.DB, knowledgeAsOf *time.Time) (vulnerabilityFinder.Output, error) {
	return StartWithKnowledge(projectURL, sbom, languageId, start, knowledge, knowledgeAsOf, nil, nil)
}

// StartWithAdvisories is Start with the advisory lookups supplied; nil reads the knowledge database.
// A failed knowledge lookup returns a failed output and an ErrKnowledgeLookup error.
func StartWithAdvisories(projectURL string, sbom sbomTypes.Output, languageId string, start time.Time, knowledge *bun.DB, knowledgeAsOf *time.Time, advisories matcher.Advisories) (vulnerabilityFinder.Output, error) {
	return StartWithKnowledge(projectURL, sbom, languageId, start, knowledge, knowledgeAsOf, nil, advisories)
}

// StartWithKnowledge is StartWithAdvisories with the knowledge snapshot the source verdicts are judged against.
// A nil snapshot leaves every source's state unknown, so an unmatched source is stale or failed.
func StartWithKnowledge(projectURL string, sbom sbomTypes.Output, languageId string, start time.Time, knowledge *bun.DB, knowledgeAsOf *time.Time, snapshot *knowledgeTypes.KnowledgeSnapshot, advisories matcher.Advisories) (vulnerabilityFinder.Output, error) {
	if sbom.AnalysisInfo.Status != codeclarity.SUCCESS {
		exceptionManager.AddError("Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED, "Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), nil
	}

	var vulnerabilityMatcher matcher.VulnerabilityMatcher

	switch languageId {
	case "JS":
		vulnerabilityMatcher = matcher.VulnerabilityMatcher{
			Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
			ConflictResolver:  conflictResolver.TrustOSVFirst,
			PackageRepository: npmRepository.NpmPackageRepository,
			KnowledgeAsOf:     knowledgeAsOf,
		}
	case "PHP":
		vulnerabilityMatcher = matcher.VulnerabilityMatcher{
			Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.PHP},
			ConflictResolver:  conflictResolver.TrustOSVFirst,
			PackageRepository: phpRepository.PhpPackageRepository,
			KnowledgeAsOf:     knowledgeAsOf,
		}
	default:
		exceptionManager.AddError("", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED, "", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), nil
	}
	vulnerabilityMatcher.Advisories = advisories
	vulnerabilityMatcher.KnowledgeSnapshot = snapshot
	failed := func(err error) (vulnerabilityFinder.Output, error) {
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), err
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
		vulns, maliciousAdvisories, err := vulnerabilityMatcher.GetWorkspaceFindings(context.Background(), workspace.Dependencies, knowledge)
		if err != nil {
			return failed(err)
		}

		// For PHP projects, also analyze PHP extension vulnerabilities
		if languageId == "PHP" {
			analyzer := extensionAnalyzer.NewPHPExtensionAnalyzer()

			// Extract extensions from SBOM
			extensions := analyzer.ExtractExtensionsFromSBOM(sbom)

			// Filter to only relevant extensions for vulnerability tracking
			relevantExtensions := analyzer.FilterRelevantExtensions(extensions)

			// Analyze extension vulnerabilities
			extensionVulns, err := analyzer.AnalyzeExtensionVulnerabilities(relevantExtensions, knowledge)
			if err != nil {
				return failed(fmt.Errorf("%w: %w", matcher.ErrKnowledgeLookup, err))
			}

			// Merge extension vulnerabilities with package vulnerabilities
			vulns = append(vulns, extensionVulns...)
		}

		// Analyze private packages for vulnerabilities (for both JS and PHP)
		privateAnalyzer := privatePackageAnalyzer.NewPrivatePackageAnalyzer(knowledge)
		privateVulns := privateAnalyzer.AnalyzePrivatePackages(sbom, workspace.Dependencies)

		// Merge private package vulnerabilities with existing vulnerabilities
		vulns = append(vulns, privateVulns...)

		workspaces[workspaceKey] = vulnerabilityFinder.Workspace{
			Vulnerabilities:            vulns,
			MaliciousPackageAdvisories: maliciousAdvisories,
		}

		user := os.Getenv("VULNERABILITY_LOOKUP_API_KEY")
		if user != "" && user != "!ChangeMe!" {
			declareSightings(projectURL, vulns)
		}
	}

	return outputGenerator.SuccessOutput(workspaces, sbom.AnalysisInfo, start), nil
}
