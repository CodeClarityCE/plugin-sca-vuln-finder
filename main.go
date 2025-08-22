package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	"sort"
	"time"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	"github.com/CodeClarityCE/utility-types/boilerplates"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
)

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
	// Prepare the arguments for the plugin
	// Get all SBOM keys from previous stages
	sbomKeys := []struct {
		id         uuid.UUID
		language   string
		pluginName string
	}{}

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
				sbomKeyUUID, err := uuid.Parse(step.Result["sbomKey"].(string))
				if err != nil {
					panic(err)
				}
				sbomKeys = append(sbomKeys, struct {
					id         uuid.UUID
					language   string
					pluginName string
				}{sbomKeyUUID, "JS", "js-sbom"})
			case "php-sbom":
				log.Printf("Found completed php-sbom in stage %d", stageIndex)
				sbomKeyUUID, err := uuid.Parse(step.Result["sbomKey"].(string))
				if err != nil {
					panic(err)
				}
				sbomKeys = append(sbomKeys, struct {
					id         uuid.UUID
					language   string
					pluginName string
				}{sbomKeyUUID, "PHP", "php-sbom"})
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
		panic(err)
	}

	log.Printf("SBOM search complete. Found %d SBOM results", len(sbomKeys))
	
	// If no SBOMs were found, return success with empty results
	if len(sbomKeys) == 0 {
		log.Printf("No SBOM results found - this might indicate SBOM plugins haven't completed yet or failed")
		vulnOutput = outputGenerator.SuccessOutput(map[string]vulnerabilityFinder.Workspace{}, sbom.AnalysisInfo{
			Status: codeclarity.SUCCESS,
		}, start)
	} else {

		// Process the first available SBOM (for now, we'll process just the first one)
		// In the future, this could be enhanced to merge multiple SBOM results
		sbomInfo := sbomKeys[0]

		res := codeclarity.Result{
			Id: sbomInfo.id,
		}
		err = databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", sbomInfo.id).Scan(context.Background())
		if err != nil {
			panic(err)
		}

		sbom := sbom.Output{}

		resultBytes := res.Result.([]byte)
		err = json.Unmarshal(resultBytes, &sbom)
		if err != nil {
			exceptionManager.AddError(
				"", exceptionManager.GENERIC_ERROR,
				fmt.Sprintf("Error when reading %s output: %s", sbomInfo.pluginName, err), exceptionManager.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
			)
			vulnOutput = outputGenerator.FailureOutput(sbom.AnalysisInfo, start)
		} else {
			vulnOutput = vulnerabilities.Start(project.Url, sbom, sbomInfo.language, start, databases.Knowledge)
		}
	}

	vuln_result := codeclarity.Result{
		Result:     vulnerabilityFinder.ConvertOutputToMap(vulnOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err = databases.Codeclarity.NewInsert().Model(&vuln_result).Exec(context.Background())
	if err != nil {
		panic(err)
	}

	// Prepare the result to store in step
	result := make(map[string]any)
	result["vulnKey"] = vuln_result.Id

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

		if workspaces, ok := workspacesAny.(map[string]vulnerabilityFinder.Workspace); ok {
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
