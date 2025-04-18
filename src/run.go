package vulnerabilities

// package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/conflictResolver"
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	outputGenerator "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	npmRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/npm"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	vulnerabilitylookup "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityLookup"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/uptrace/bun"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
)

// Start starts a vulnerability analysis on the given sbom
func Start(projectURL string, sbom sbomTypes.Output, languageId string, start time.Time, knowledge *bun.DB) vulnerabilityFinder.Output {
	if sbom.AnalysisInfo.Status != codeclarity.SUCCESS {
		exceptionManager.AddError("Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED, "Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
	}

	var vulnerabilityMatcher matcher.VulnerabilityMatcher

	if languageId == "JS" {
		vulnerabilityMatcher = matcher.VulnerabilityMatcher{
			Ecosystems:        []ecosystemTypes.Ecosystem{ecosystemTypes.NODEJS_OR_JS},
			ConflictResolver:  conflictResolver.TrustOSV,
			PackageRepository: npmRepository.NpmPackageRepository,
		}
	} else {
		exceptionManager.AddError("", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED, "", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
	}

	workspaces := map[string]vulnerabilityFinder.Workspace{}
	for workspaceKey, workspace := range sbom.WorkSpaces {
		vulns := vulnerabilityMatcher.GetWorkspaceVulnerabilities(workspace.Dependencies, knowledge)
		workspaces[workspaceKey] = vulnerabilityFinder.Workspace{
			Vulnerabilities: vulns,
		}

		user := os.Getenv("VULNERABILITY_LOOKUP_API_KEY")
		if user != "" && user != "!ChangeMe!" {
			// If the repository is public, we declare sightings to vulnerability lookup
			// Send a http GET request on projectURL
			resp, err := http.Get(projectURL)
			if err != nil || resp.StatusCode == 403 {
				continue
			}
			defer resp.Body.Close()
			// Process the response body
			body, err := io.ReadAll(resp.Body)
			if err != nil || strings.Contains(string(body), "Page not found") {
				continue
			}
			for _, vuln := range vulns {
				vulnerabilitylookup.DeclareSighting(vuln, projectURL)
			}

		}
	}

	return outputGenerator.SuccessOutput(workspaces, sbom.AnalysisInfo, start)
}
