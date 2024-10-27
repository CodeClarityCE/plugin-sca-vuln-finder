package ecosystemAnalyzer

import (
	advisoryAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/analyzers/advisory"
	correlactorAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/analyzers/correlator"
	cpeAnalyzer "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/analyzers/cpe"
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
)

// InferNVDMatchesEcosystems infers the ecosystems of a given list of nvd matches
//
// The NVD does not denote what ecosystem(s) a vulnerability affects
// This means for a vulnerability that affectes product "xy" we do not know if it
// affects the python package called "xy" and the js package called "xy" or both
//
// Based on a compiled list of indicators this method "infers" the ecosystem from the vulnerability information provided by the NVD
func InferNVDMatchEcosystems(match vulnerabilityFinder.NVDVulnerability) []ecosystemTypes.Ecosystem {

	inferredEcoSystems := []ecosystemTypes.Ecosystem{}

	// 1. Check if the osv database has a entry in their database
	inferredEcoSystems = append(inferredEcoSystems, correlactorAnalyzer.InferEcosystemOSVCorrelator(match)...)
	if len(inferredEcoSystems) > 0 {
		return inferredEcoSystems
	}

	// 2. If the osv database does not have an entry for this vulnerability
	inferredEcoSystems = append(inferredEcoSystems, correlactorAnalyzer.InferEcosystemOSVCorrelator(match)...)
	inferredEcoSystems = append(inferredEcoSystems, cpeAnalyzer.InferEcosystemCpeProduct(match)...)
	inferredEcoSystems = append(inferredEcoSystems, cpeAnalyzer.InferEcosystemCpeTarget(match)...)
	inferredEcoSystems = append(inferredEcoSystems, cpeAnalyzer.InferEcosystemCpeVendor(match)...)
	inferredEcoSystems = append(inferredEcoSystems, advisoryAnalyzer.InferEcosystemAdvisoryUrlExtractor(match)...)

	return inferredEcoSystems
}
