package outputGenerator

import (
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
)

// SuccessOutput generates the output for a successful vulnerability analysis.
// It takes in the workspaceData, sbomAnalysisInfo, and start time as parameters.
// It returns an instance of vulnerabilityFinder.Output containing the generated output.
func SuccessOutput(workspaceData map[string]vulnerabilityFinder.Workspace, sbomAnalysisInfo sbomTypes.AnalysisInfo, start time.Time) vulnerabilityFinder.Output {
	return vulnerabilityFinder.Output{
		WorkSpaces: workspaceData,
		AnalysisInfo: vulnerabilityFinder.AnalysisInfo{
			Status:            codeclarity.SUCCESS,
			AnalysisStartTime: start.Local().String(),
			AnalysisEndTime:   time.Now().Local().String(),
			AnalysisDeltaTime: time.Since(start).Seconds(),
			Errors:            exceptionManager.GetErrors(),
		},
	}
}

// FailureOutput generates the output for a failed analysis.
// It takes the sbomAnalysisInfo as input, which contains information about the analysis.
// The start time of the analysis is also provided as input.
// It returns the generated output, which includes the analysis status, workspaces data, and analysis timing.
func FailureOutput(sbomAnalysisInfo sbomTypes.AnalysisInfo, start time.Time) vulnerabilityFinder.Output {
	return vulnerabilityFinder.Output{
		AnalysisInfo: vulnerabilityFinder.AnalysisInfo{
			Status:            codeclarity.FAILURE,
			AnalysisStartTime: start.Local().String(),
			AnalysisEndTime:   time.Now().Local().String(),
			AnalysisDeltaTime: time.Since(start).Seconds(),
			Errors:            exceptionManager.GetErrors(),
		},
		WorkSpaces: map[string]vulnerabilityFinder.Workspace{},
	}
}

// getAnalysisTiming calculates the analysis timing by measuring the elapsed time between the start and end points.
// It returns the start time, end time, and elapsed time in seconds.
func getAnalysisTiming(start time.Time) (string, string, float64) {
	return start.Local().String(), time.Now().Local().String(), time.Since(start).Seconds()
}
