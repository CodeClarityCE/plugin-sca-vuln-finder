package main

import (
	"context"
	"encoding/json"
	"fmt"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	"log"
	"sort"
	"time"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/utility-boilerplates"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
)

// sbomKey identifies one SBOM result to process.
type sbomKey struct {
	id         uuid.UUID
	language   string
	pluginName string
}

// VulnFinderAnalysisHandler implements the AnalysisHandler interface
type VulnFinderAnalysisHandler struct{}

// StartAnalysis implements the AnalysisHandler interface
func (h *VulnFinderAnalysisHandler) StartAnalysis(
	databases *boilerplates.PluginDatabases,
	dispatcherMessage types_amqp.DispatcherPluginMessage,
	config plugin.Plugin,
	analysisDoc codeclarity.Analysis,
) (map[string]any, codeclarity.AnalysisStatus, error) {
	return startAnalysis(databases, dispatcherMessage, config, analysisDoc)
}

// main is the entry point of the program.
func main() {
	pluginBase, err := boilerplates.CreatePluginBase()
	if err != nil {
		log.Fatalf("Failed to initialize plugin base: %v", err)
	}
	defer pluginBase.Close()

	// Start the plugin with our analysis handler
	handler := &VulnFinderAnalysisHandler{}
	err = pluginBase.Listen(handler)
	if err != nil {
		log.Fatalf("Failed to start plugin: %v", err)
	}
}

func startAnalysis(databases *boilerplates.PluginDatabases, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
	// Read the optional per-analysis knowledge as-of cutoff (YYYY-MM-DD).
	// A missing config map, missing key, or empty string means no filter; a
	// present but invalid value fails the analysis, because a typo silently
	// producing unfiltered results would corrupt the study.
	var knowledgeAsOf *time.Time
	knowledgeAsOfStr := ""
	if pluginConfig, ok := analysis_document.Config[config.Name].(map[string]any); ok {
		if raw, present := pluginConfig["knowledge_asof"]; present && raw != nil {
			str, ok := raw.(string)
			if !ok {
				return nil, codeclarity.FAILURE, fmt.Errorf("invalid knowledge_asof config value %v: expected a YYYY-MM-DD string", raw)
			}
			if str != "" {
				parsed, err := time.Parse("2006-01-02", str)
				if err != nil {
					return nil, codeclarity.FAILURE, fmt.Errorf("invalid knowledge_asof date %q (expected YYYY-MM-DD): %w", str, err)
				}
				knowledgeAsOf = &parsed
				knowledgeAsOfStr = str
				log.Printf("Knowledge as-of filter active: %s", knowledgeAsOfStr)
			}
		}
	}

	// Prepare the arguments for the plugin
	// Get all SBOM keys from previous stages
	sbomKeys := []sbomKey{}

	// Look for SBOM results in all completed stages, not just the "previous" stage
	// This makes vuln-finder more flexible with dispatcher scheduling
	log.Printf("Scanning all stages for SBOM results. Current stage: %d, Total stages: %d", analysis_document.Stage, len(analysis_document.Steps))

	// Search through all stages to find completed SBOM plugins
	for stageIndex := 0; stageIndex < len(analysis_document.Steps); stageIndex++ {
		log.Printf("Checking stage %d for SBOM results", stageIndex)
		for _, step := range analysis_document.Steps[stageIndex] {
			// Only process completed steps that have results
			if step.Status != codeclarity.SUCCESS || step.Result == nil {
				continue
			}

			switch step.Name {
			case "js-sbom":
				log.Printf("Found completed js-sbom in stage %d", stageIndex)
				sbomKeyStr, ok := step.Result["sbomKey"].(string)
				if !ok {
					return nil, codeclarity.FAILURE, fmt.Errorf("js-sbom result at stage %d has no sbomKey", stageIndex)
				}
				sbomKeyUUID, err := uuid.Parse(sbomKeyStr)
				if err != nil {
					return nil, codeclarity.FAILURE, fmt.Errorf("invalid js-sbom key: %w", err)
				}
				sbomKeys = append(sbomKeys, sbomKey{sbomKeyUUID, "JS", "js-sbom"})
			case "php-sbom":
				log.Printf("Found completed php-sbom in stage %d", stageIndex)
				sbomKeyStr, ok := step.Result["sbomKey"].(string)
				if !ok {
					return nil, codeclarity.FAILURE, fmt.Errorf("php-sbom result at stage %d has no sbomKey", stageIndex)
				}
				sbomKeyUUID, err := uuid.Parse(sbomKeyStr)
				if err != nil {
					return nil, codeclarity.FAILURE, fmt.Errorf("invalid php-sbom key: %w", err)
				}
				sbomKeys = append(sbomKeys, sbomKey{sbomKeyUUID, "PHP", "php-sbom"})
			}
		}
	}

	var vulnOutput vulnerabilityFinder.Output
	start := time.Now()

	// Get project info (needed for both success and failure cases)
	project := codeclarity.Project{
		Id: *analysis_document.ProjectId,
	}
	err := databases.Codeclarity.NewSelect().Model(&project).WherePK().Scan(context.Background())
	if err != nil {
		return nil, codeclarity.FAILURE, fmt.Errorf("failed to fetch project: %w", err)
	}

	log.Printf("SBOM search complete. Found %d SBOM results", len(sbomKeys))

	// Log analysis configuration for debugging
	log.Printf("=== VULNERABILITY FINDER ANALYSIS DEBUG ===")
	log.Printf("Analysis ID: %s", dispatcherMessage.AnalysisId.String())
	log.Printf("Project ID: %s", project.Id.String())
	log.Printf("Project URL: %s", project.Url)

	// If no SBOMs were found, return success with empty results
	if len(sbomKeys) == 0 {
		log.Printf("No SBOM results found - this might indicate SBOM plugins haven't completed yet or failed")
		vulnOutput = outputGenerator.SuccessOutput(map[string]vulnerabilityFinder.Workspace{}, sbom.AnalysisInfo{
			Status: codeclarity.SUCCESS,
		}, start)
	} else {
		vulnOutput = combineVulnOutputs(sbomKeys, func(sbomInfo sbomKey) (vulnerabilityFinder.Output, error) {
			return analyzeSbom(databases, sbomInfo, project.Url, start, knowledgeAsOf)
		}, start)
	}

	vuln_result := codeclarity.Result{
		Result:     vulnerabilityFinder.ConvertOutputToMap(vulnOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err = databases.Codeclarity.NewInsert().Model(&vuln_result).Exec(context.Background())
	if err != nil {
		return nil, codeclarity.FAILURE, fmt.Errorf("failed to insert vulnerability result: %w", err)
	}

	// Prepare the result to store in step
	result := make(map[string]any)
	result["vulnKey"] = vuln_result.Id
	if knowledgeAsOf != nil {
		result["knowledgeAsOf"] = knowledgeAsOfStr
	}

	// Build vuln summary for notifier
	if vulnOutput.AnalysisInfo.Status == codeclarity.SUCCESS {
		// Extract vulnerabilities from output map
		workspacesAny := vulnerabilityFinder.ConvertOutputToMap(vulnOutput)["workspaces"]
		severityCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
		type topVuln struct {
			VulnerabilityId string  `json:"vulnerability_id"`
			Dependency      string  `json:"dependency"`
			AffectedVersion string  `json:"affected_version"`
			SeverityClass   string  `json:"severity_class"`
			SeverityScore   float64 `json:"severity_score"`
		}

		// Track unique vulnerabilities to avoid double counting
		uniqueVulns := make(map[string]topVuln)

		log.Printf("=== BUILDING NOTIFICATION SUMMARY ===")
		if workspaces, ok := workspacesAny.(map[string]vulnerabilityFinder.Workspace); ok {
			totalBeforeDedup := 0
			for wsName, ws := range workspaces {
				totalBeforeDedup += len(ws.Vulnerabilities)
				log.Printf("Processing workspace '%s' with %d vulnerabilities for summary", wsName, len(ws.Vulnerabilities))
			}
			log.Printf("Total vulnerabilities before deduplication: %d", totalBeforeDedup)

			for _, ws := range workspaces {
				for _, v := range ws.Vulnerabilities {
					// Only count each unique vulnerability ID once
					if existing, exists := uniqueVulns[v.VulnerabilityId]; !exists || v.Severity.Severity > existing.SeverityScore {
						// If new vulnerability or higher severity version found, use it
						uniqueVulns[v.VulnerabilityId] = topVuln{
							VulnerabilityId: v.VulnerabilityId,
							Dependency:      v.AffectedDependency,
							AffectedVersion: v.AffectedVersion,
							SeverityClass:   string(v.Severity.SeverityClass),
							SeverityScore:   v.Severity.Severity,
						}
					}
				}
			}

			// Count unique vulnerabilities by severity
			var tops []topVuln
			for _, vuln := range uniqueVulns {
				severityCounts[vuln.SeverityClass]++
				tops = append(tops, vuln)
			}
			total := len(uniqueVulns)
			log.Printf("After deduplication: %d unique vulnerabilities", total)
			log.Printf("Severity counts: CRITICAL=%d, HIGH=%d, MEDIUM=%d, LOW=%d, NONE=%d",
				severityCounts["CRITICAL"], severityCounts["HIGH"],
				severityCounts["MEDIUM"], severityCounts["LOW"], severityCounts["NONE"])

			// sort by severity desc
			sort.Slice(tops, func(i, j int) bool { return tops[i].SeverityScore > tops[j].SeverityScore })
			if len(tops) > 5 {
				tops = tops[:5]
			}
			maxSeverity := "NONE"
			for _, order := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
				if severityCounts[order] > 0 {
					maxSeverity = order
					break
				}
			}
			log.Printf("Max severity: %s", maxSeverity)
			notif := map[string]any{
				"type":            "vuln_summary",
				"analysis_id":     dispatcherMessage.AnalysisId,
				"organization_id": analysis_document.OrganizationId,
				"project_id":      analysis_document.ProjectId,
				"project_name":    project.Name,
				"total":           total,
				"severity_counts": severityCounts,
				"max_severity":    maxSeverity,
				"top":             tops,
			}
			data, _ := json.Marshal(notif)
			amqp_helper.Send("service_notifier", data)
		}
	}

	// The output is always a map[string]any
	return result, vulnOutput.AnalysisInfo.Status, nil
}

// analyzeSbom loads one stored SBOM and runs vulnerability detection on it.
func analyzeSbom(databases *boilerplates.PluginDatabases, sbomInfo sbomKey, projectUrl string, start time.Time, knowledgeAsOf *time.Time) (vulnerabilityFinder.Output, error) {
	log.Printf("Processing SBOM: ID=%s, Language=%s, Plugin=%s", sbomInfo.id.String(), sbomInfo.language, sbomInfo.pluginName)

	res := codeclarity.Result{Id: sbomInfo.id}
	err := databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", sbomInfo.id).Scan(context.Background())
	if err != nil {
		return vulnerabilityFinder.Output{}, fmt.Errorf("fetch SBOM result %s: %w", sbomInfo.id, err)
	}
	resultBytes, ok := res.Result.([]byte)
	if !ok {
		return vulnerabilityFinder.Output{}, fmt.Errorf("SBOM result of %s is not stored as bytes", sbomInfo.pluginName)
	}

	sbomOutput := sbom.Output{}
	if err = json.Unmarshal(resultBytes, &sbomOutput); err != nil {
		exceptionManager.AddError(
			"", exceptionManager.GENERIC_ERROR,
			fmt.Sprintf("Error when reading %s output: %s", sbomInfo.pluginName, err), exceptionManager.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
		)
		return vulnerabilityFinder.Output{}, fmt.Errorf("read %s output: %w", sbomInfo.pluginName, err)
	}

	// Log SBOM details before vulnerability detection
	log.Printf("SBOM contains %d workspaces", len(sbomOutput.WorkSpaces))
	totalPackages := 0
	for workspace, deps := range sbomOutput.WorkSpaces {
		log.Printf("Workspace '%s': %d dependencies", workspace, len(deps.Dependencies))
		totalPackages += len(deps.Dependencies)
	}
	log.Printf("Total packages across all workspaces: %d", totalPackages)

	return vulnerabilities.Start(projectUrl, sbomOutput, sbomInfo.language, start, databases.Knowledge, knowledgeAsOf), nil
}

// combineVulnOutputs merges the vulnerability results of every SBOM.
// One SBOM that cannot be analyzed fails the step, so no ecosystem goes missing.
func combineVulnOutputs(sbomKeys []sbomKey, analyze func(sbomKey) (vulnerabilityFinder.Output, error), start time.Time) vulnerabilityFinder.Output {
	failed := func() vulnerabilityFinder.Output {
		return outputGenerator.FailureOutput(sbom.AnalysisInfo{Status: codeclarity.FAILURE}, start)
	}
	mergedWorkspaces := map[string]vulnerabilityFinder.Workspace{}

	for _, sbomInfo := range sbomKeys {
		langOutput, err := analyze(sbomInfo)
		if err != nil {
			log.Printf("Vulnerability detection failed: %v", err)
			return failed()
		}
		if langOutput.AnalysisInfo.Status != codeclarity.SUCCESS {
			log.Printf("[%s] Vulnerability detection failed with status: %s", sbomInfo.language, langOutput.AnalysisInfo.Status)
			return failed()
		}

		// Merge workspaces: append vulnerabilities when workspace keys overlap
		for wsKey, ws := range langOutput.WorkSpaces {
			if existing, ok := mergedWorkspaces[wsKey]; ok {
				existing.Vulnerabilities = append(existing.Vulnerabilities, ws.Vulnerabilities...)
				mergedWorkspaces[wsKey] = existing
			} else {
				mergedWorkspaces[wsKey] = ws
			}
		}

		// Log vulnerability detection results for this language
		totalVulns := 0
		for wsName, ws := range langOutput.WorkSpaces {
			vulnCount := len(ws.Vulnerabilities)
			totalVulns += vulnCount
			log.Printf("[%s] Workspace '%s': %d vulnerabilities", sbomInfo.language, wsName, vulnCount)
		}
		log.Printf("[%s] TOTAL VULNERABILITIES DETECTED: %d", sbomInfo.language, totalVulns)
	}

	totalMerged := 0
	for wsName, ws := range mergedWorkspaces {
		totalMerged += len(ws.Vulnerabilities)
		log.Printf("Merged workspace '%s': %d vulnerabilities", wsName, len(ws.Vulnerabilities))
	}
	log.Printf("TOTAL MERGED VULNERABILITIES: %d across %d workspaces", totalMerged, len(mergedWorkspaces))

	return outputGenerator.SuccessOutput(mergedWorkspaces, sbom.AnalysisInfo{Status: codeclarity.SUCCESS}, start)
}
