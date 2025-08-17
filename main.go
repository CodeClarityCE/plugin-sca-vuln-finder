package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilities "github.com/CodeClarityCE/plugin-sca-vuln-finder/src"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/outputGenerator"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	amqp_helper "github.com/CodeClarityCE/utility-amqp-helper"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	plugin "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// Define the arguments you want to pass to the callback function
type Arguments struct {
	codeclarity *bun.DB
	knowledge   *bun.DB
}

// main is the entry point of the program.
// It reads the configuration, initializes the necessary databases and graph,
// and starts listening on the queue.
func main() {
	config, err := readConfig()
	if err != nil {
		log.Printf("%v", err)
		return
	}

	host := os.Getenv("PG_DB_HOST")
	if host == "" {
		log.Printf("PG_DB_HOST is not set")
		return
	}
	port := os.Getenv("PG_DB_PORT")
	if port == "" {
		log.Printf("PG_DB_PORT is not set")
		return
	}
	user := os.Getenv("PG_DB_USER")
	if user == "" {
		log.Printf("PG_DB_USER is not set")
		return
	}
	password := os.Getenv("PG_DB_PASSWORD")
	if password == "" {
		log.Printf("PG_DB_PASSWORD is not set")
		return
	}

	dsn_knowledge := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge), pgdriver.WithTimeout(120*time.Second)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbhelper.Config.Database.Results + "?sslmode=disable"
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn), pgdriver.WithTimeout(120*time.Second)))
	db_codeclarity := bun.NewDB(sqldb, pgdialect.New())
	defer db_codeclarity.Close()

	args := Arguments{
		codeclarity: db_codeclarity,
		knowledge:   db_knowledge,
	}

	// Start listening on the queue
	amqp_helper.Listen("dispatcher_"+config.Name, callback, args, config)
}

func startAnalysis(args Arguments, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
	// Prepare the arguments for the plugin
	// Get all SBOM keys from previous stages
	sbomKeys := []struct {
		id         uuid.UUID
		language   string
		pluginName string
	}{}

	// Vuln-finder depends on SBOM plugins, so it should never be at stage 0
	// If we're at stage 0, it means the dispatcher hasn't properly updated the stage yet
	if analysis_document.Stage == 0 {
		return nil, codeclarity.FAILURE, fmt.Errorf("vuln-finder cannot run at stage 0 - depends on SBOM plugins")
	}

	// Get previous stage where SBOM plugins ran
	analysis_stage := analysis_document.Stage - 1

	// Safety check: ensure we have a valid previous stage
	if analysis_stage >= len(analysis_document.Steps) {
		return nil, codeclarity.FAILURE, fmt.Errorf("invalid analysis stage %d - exceeds available stages (total: %d)", analysis_stage, len(analysis_document.Steps))
	}

	for _, step := range analysis_document.Steps[analysis_stage] {
		switch step.Name {
		case "js-sbom":
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


	var vulnOutput vulnerabilityFinder.Output
	start := time.Now()

	// Get project info (needed for both success and failure cases)
	project := codeclarity.Project{
		Id: *analysis_document.ProjectId,
	}
	err := args.codeclarity.NewSelect().Model(&project).WherePK().Scan(context.Background())
	if err != nil {
		panic(err)
	}

	// If no SBOMs were found, return success with empty results
	if len(sbomKeys) == 0 {
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
		err = args.codeclarity.NewSelect().Model(&res).Where("id = ?", sbomInfo.id).Scan(context.Background())
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
			vulnOutput = vulnerabilities.Start(project.Url, sbom, sbomInfo.language, start, args.knowledge)
		}
	}

	vuln_result := codeclarity.Result{
		Result:     vulnerabilityFinder.ConvertOutputToMap(vulnOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err = args.codeclarity.NewInsert().Model(&vuln_result).Exec(context.Background())
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
