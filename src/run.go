package vulnerabilities

// package main

import (
	"time"

	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/conflictResolver"
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	outputGenerator "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	npmRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/npm"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	"github.com/uptrace/bun"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
)

// Start starts a vulnerability analysis on the given sbom
func Start(sbom sbomTypes.Output, languageId string, start time.Time, knowledge *bun.DB) vulnerabilityFinder.Output {
	if sbom.AnalysisInfo.Status != codeclarity.SUCCESS {
		exceptionManager.AddError("Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptions.PREVIOUS_STAGE_FAILED, "Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptions.PREVIOUS_STAGE_FAILED)
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
		exceptionManager.AddError("", exceptions.UNSUPPORTED_LANGUAGE_REQUESTED, "", exceptions.UNSUPPORTED_LANGUAGE_REQUESTED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
	}

	workspaces := map[string]vulnerabilityFinder.Workspace{}
	for workspaceKey, workspace := range sbom.WorkSpaces {
		vulns := vulnerabilityMatcher.GetWorkspaceVulnerabilities(workspace.Dependencies, knowledge)
		workspaces[workspaceKey] = vulnerabilityFinder.Workspace{
			Vulnerabilities: vulns,
		}
	}

	return outputGenerator.SuccessOutput(workspaces, sbom.AnalysisInfo, start)
}
