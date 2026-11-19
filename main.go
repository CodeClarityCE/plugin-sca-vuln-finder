package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	"log"
	"sort"
	"time"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/sourcesync"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	matcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher"
	"github.com/CodeClarityCE/utility-boilerplates"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

const invalidKnowledgeDateReason = "the knowledge date is not valid, use the YYYY-MM-DD format"

const knowledgeLookupReason = "the vulnerability database could not be read, try the analysis again"

// stepFailure logs the raw cause and returns a failed step that carries a readable reason.
func stepFailure(reason string, cause error) (map[string]any, codeclarity.AnalysisStatus, error) {
	log.Printf("Vulnerability finder failed: %s: %v", reason, cause)
	return map[string]any{codeclarity.StepFailureReasonKey: reason}, codeclarity.FAILURE, nil
}

// firstReason keeps the earlier failure when a later step also fails.
func firstReason(earlier, later string) string {
	if earlier != "" {
		return earlier
	}
	return later
}

// languageName spells out an SBOM language for people to read.
func languageName(language string) string {
	if language == "JS" {
		return "JavaScript"
	}
	return language
}

func missingSbomReason(language string) string {
	return fmt.Sprintf("the %s dependency list could not be found", languageName(language))
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
				return stepFailure(invalidKnowledgeDateReason, fmt.Errorf("invalid knowledge_asof config value %v", raw))
			}
			if str != "" {
				parsed, err := time.Parse("2006-01-02", str)
				if err != nil {
					return stepFailure(invalidKnowledgeDateReason, fmt.Errorf("invalid knowledge_asof date %q: %w", str, err))
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
					return stepFailure(missingSbomReason("JS"), fmt.Errorf("js-sbom result at stage %d has no sbomKey", stageIndex))
				}
				sbomKeyUUID, err := uuid.Parse(sbomKeyStr)
				if err != nil {
					return stepFailure(missingSbomReason("JS"), fmt.Errorf("invalid js-sbom key: %w", err))
				}
				sbomKeys = append(sbomKeys, sbomKey{sbomKeyUUID, "JS", "js-sbom"})
			case "php-sbom":
				log.Printf("Found completed php-sbom in stage %d", stageIndex)
				sbomKeyStr, ok := step.Result["sbomKey"].(string)
				if !ok {
					return stepFailure(missingSbomReason("PHP"), fmt.Errorf("php-sbom result at stage %d has no sbomKey", stageIndex))
				}
				sbomKeyUUID, err := uuid.Parse(sbomKeyStr)
				if err != nil {
					return stepFailure(missingSbomReason("PHP"), fmt.Errorf("invalid php-sbom key: %w", err))
				}
				sbomKeys = append(sbomKeys, sbomKey{sbomKeyUUID, "PHP", "php-sbom"})
			}
		}
	}

	var vulnOutput vulnerabilityFinder.Output
	failureReason := ""
	start := time.Now()

	// Get project info (needed for both success and failure cases)
	project := codeclarity.Project{
		Id: *analysis_document.ProjectId,
	}
	err := databases.Codeclarity.NewSelect().Model(&project).WherePK().Scan(context.Background())
	if err != nil {
		return stepFailure("the project could not be loaded", fmt.Errorf("failed to fetch project: %w", err))
	}

	log.Printf("SBOM search complete. Found %d SBOM results", len(sbomKeys))

	// Log analysis configuration for debugging
	log.Printf("=== VULNERABILITY FINDER ANALYSIS DEBUG ===")
	log.Printf("Analysis ID: %s", dispatcherMessage.AnalysisId.String())
	log.Printf("Project ID: %s", project.Id.String())
	log.Printf("Project URL: %s", project.Url)

	// Taken before matching so it describes the knowledge the results were built from.
	snapshot := sourcesync.Snapshot(context.Background(), databases.Knowledge, time.Now().UTC(), knowledgeAsOf)
	vulnOutput, failureReason = buildVulnOutput(sbomKeys, func(sbomInfo sbomKey) (vulnerabilityFinder.Output, error) {
		output, err := analyzeSbom(databases, sbomInfo, project.Url, start, knowledgeAsOf, &snapshot)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"analysis_id": dispatcherMessage.AnalysisId.String(),
				"project_id":  project.Id.String(),
				"language":    sbomInfo.language,
			}).WithError(err).Error("Vulnerability detection failed")
		}
		return output, err
	}, start, snapshot)

	vuln_result := codeclarity.Result{
		Result:     vulnerabilityFinder.ConvertOutputToMap(vulnOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err = databases.Codeclarity.NewInsert().Model(&vuln_result).Exec(context.Background())
	if err != nil {
		return stepFailure(firstReason(failureReason, "the vulnerability results could not be saved"), fmt.Errorf("failed to insert vulnerability result: %w", err))
	}

	// Prepare the result to store in step
	result := make(map[string]any)
	result["vulnKey"] = vuln_result.Id
	if failureReason != "" {
		result[codeclarity.StepFailureReasonKey] = failureReason
	}
	if knowledgeAsOf != nil {
		result["knowledgeAsOf"] = knowledgeAsOfStr
	}

	// Build vuln summary for notifier
	if vulnOutput.AnalysisInfo.Status == codeclarity.SUCCESS {
		// Extract vulnerabilities from output map
		workspacesAny := vulnerabilityFinder.ConvertOutputToMap(vulnOutput)["workspaces"]
		if workspaces, ok := workspacesAny.(map[string]vulnerabilityFinder.Workspace); ok {
			summary := buildVulnSummary(workspaces)
			log.Printf("Notification summary: %d unique vulnerabilities, max severity %s, hidden %v", summary.Total, summary.MaxSeverity, summary.HiddenCounts)
			notif := map[string]any{
				"type":            "vuln_summary",
				"analysis_id":     dispatcherMessage.AnalysisId,
				"organization_id": analysis_document.OrganizationId,
				"project_id":      analysis_document.ProjectId,
				"project_name":    project.Name,
				"total":           summary.Total,
				"severity_counts": summary.SeverityCounts,
				"max_severity":    summary.MaxSeverity,
				"top":             summary.Top,
				"hidden_counts":   summary.HiddenCounts,
			}
			data, _ := json.Marshal(notif)
			// A lost notification must not fail an analysis that already succeeded.
			if err := amqp_helper.TrySend("service_notifier", data); err != nil {
				log.Printf("Failed to send vulnerability notification: %v", err)
			}
		}
	}

	// The output is always a map[string]any
	return result, vulnOutput.AnalysisInfo.Status, nil
}

// summaryVuln is one vulnerability listed in the notification summary.
type summaryVuln struct {
	VulnerabilityId string  `json:"vulnerability_id"`
	Dependency      string  `json:"dependency"`
	AffectedVersion string  `json:"affected_version"`
	SeverityClass   string  `json:"severity_class"`
	SeverityScore   float64 `json:"severity_score"`
}

// vulnSummary is what the notifier is told about an analysis's vulnerabilities.
type vulnSummary struct {
	Total          int
	SeverityCounts map[string]int
	MaxSeverity    string
	Top            []summaryVuln
	// HiddenCounts counts the instances hidden by default, by reason; they are left out of the rest.
	HiddenCounts map[string]int
}

// buildVulnSummary counts each vulnerability once at its worst severity, leaving out
// the instances the default view hides.
func buildVulnSummary(workspaces map[string]vulnerabilityFinder.Workspace) vulnSummary {
	summary := vulnSummary{
		SeverityCounts: map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0},
		MaxSeverity:    "NONE",
		HiddenCounts:   map[string]int{hiddenContradicted: 0, hiddenRetiredAll: 0},
	}
	unique := map[string]summaryVuln{}
	for _, ws := range workspaces {
		for _, v := range ws.Vulnerabilities {
			if hidden, _ := instanceStatus(v.SourceVerdicts); hidden != "" {
				summary.HiddenCounts[hidden]++
				continue
			}
			if existing, exists := unique[v.VulnerabilityId]; !exists || v.Severity.Severity > existing.SeverityScore {
				unique[v.VulnerabilityId] = summaryVuln{
					VulnerabilityId: v.VulnerabilityId,
					Dependency:      v.AffectedDependency,
					AffectedVersion: v.AffectedVersion,
					SeverityClass:   string(v.Severity.SeverityClass),
					SeverityScore:   v.Severity.Severity,
				}
			}
		}
	}
	for _, vuln := range unique {
		summary.SeverityCounts[vuln.SeverityClass]++
		summary.Top = append(summary.Top, vuln)
	}
	summary.Total = len(unique)
	sort.Slice(summary.Top, func(i, j int) bool { return summary.Top[i].SeverityScore > summary.Top[j].SeverityScore })
	if len(summary.Top) > 5 {
		summary.Top = summary.Top[:5]
	}
	for _, order := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if summary.SeverityCounts[order] > 0 {
			summary.MaxSeverity = order
			break
		}
	}
	return summary
}

// analyzeSbom loads one stored SBOM and runs vulnerability detection on it.
func analyzeSbom(databases *boilerplates.PluginDatabases, sbomInfo sbomKey, projectUrl string, start time.Time, knowledgeAsOf *time.Time, snapshot *knowledge.KnowledgeSnapshot) (vulnerabilityFinder.Output, error) {
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

	return vulnerabilities.StartWithKnowledge(projectUrl, sbomOutput, sbomInfo.language, start, databases.Knowledge, knowledgeAsOf, snapshot, nil)
}

// buildVulnOutput runs detection on every SBOM, or returns an empty success when there is none, and records the knowledge snapshot.
func buildVulnOutput(sbomKeys []sbomKey, analyze func(sbomKey) (vulnerabilityFinder.Output, error), start time.Time, snapshot knowledge.KnowledgeSnapshot) (vulnerabilityFinder.Output, string) {
	var output vulnerabilityFinder.Output
	reason := ""
	if len(sbomKeys) == 0 {
		log.Printf("No SBOM results found - this might indicate SBOM plugins haven't completed yet or failed")
		output = outputGenerator.SuccessOutput(map[string]vulnerabilityFinder.Workspace{}, sbom.AnalysisInfo{
			Status: codeclarity.SUCCESS,
		}, start)
	} else {
		output, reason = combineVulnOutputs(sbomKeys, analyze, start)
	}
	output.AnalysisInfo.KnowledgeSnapshot = &snapshot
	return output, reason
}

// combineVulnOutputs merges the vulnerability results of every SBOM and says why it failed, if it did.
// One SBOM that cannot be analyzed fails the step, so no ecosystem goes missing.
func combineVulnOutputs(sbomKeys []sbomKey, analyze func(sbomKey) (vulnerabilityFinder.Output, error), start time.Time) (vulnerabilityFinder.Output, string) {
	failed := func(reason string) (vulnerabilityFinder.Output, string) {
		return outputGenerator.FailureOutput(sbom.AnalysisInfo{Status: codeclarity.FAILURE}, start), reason
	}
	mergedWorkspaces := map[string]vulnerabilityFinder.Workspace{}

	for _, sbomInfo := range sbomKeys {
		langOutput, err := analyze(sbomInfo)
		if errors.Is(err, matcher.ErrKnowledgeLookup) {
			return failed(knowledgeLookupReason)
		}
		if err != nil {
			return failed(fmt.Sprintf("the %s dependency list could not be read", languageName(sbomInfo.language)))
		}
		if langOutput.AnalysisInfo.Status != codeclarity.SUCCESS {
			log.Printf("[%s] Vulnerability detection failed with status: %s", sbomInfo.language, langOutput.AnalysisInfo.Status)
			return failed(fmt.Sprintf("the %s dependencies could not be checked for vulnerabilities", languageName(sbomInfo.language)))
		}

		// Merge workspaces: append vulnerabilities when workspace keys overlap
		for wsKey, ws := range langOutput.WorkSpaces {
			if existing, ok := mergedWorkspaces[wsKey]; ok {
				existing.Vulnerabilities = append(existing.Vulnerabilities, ws.Vulnerabilities...)
				existing.MaliciousPackageAdvisories = append(existing.MaliciousPackageAdvisories, ws.MaliciousPackageAdvisories...)
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

	return outputGenerator.SuccessOutput(mergedWorkspaces, sbom.AnalysisInfo{Status: codeclarity.SUCCESS}, start), ""
}
