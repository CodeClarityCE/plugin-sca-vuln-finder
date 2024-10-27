package correlator

import (
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
)

// InferEcosystemOSVCorrelator is a function that infers the ecosystem of a vulnerability match
// based on the OSV report. It takes a pointer to a NVDVulnerabilityMatch as input and returns
// a slice of Ecosystem types.
//
// The function first retrieves the OSV report for the given vulnerability ID. If an error occurs,
// it adds the Ecosystem type OTHER to the result slice. Otherwise, it iterates over the affected
// ranges in the OSV report and checks if the affected package name matches the affected dependency
// name in the vulnerability match. Based on the ecosystem of the affected package, it appends the
// corresponding Ecosystem type to the result slice.
//
// The supported ecosystems and their corresponding Ecosystem types are as follows:
// - PyPI: PYTHON
// - Maven: JAVA
// - Android: JAVA
// - npm: NODEJS_OR_JS
// - Packagist: PHP
// - Go: GO
// - RubyGems: RUBY
// - crates.io: RUST
// - NuGet: DOTNET
// - Hex: ERLANG
// - Linux: NATIVE_OR_OS
// - OSS-Fuzz: NATIVE_OR_OS
// - Debian: NATIVE_OR_OS
// - Other: OTHER
//
// The function returns the resulting slice of Ecosystem types.
func InferEcosystemOSVCorrelator(match vulnerabilityFinder.NVDVulnerability) []ecosystemTypes.Ecosystem {

	ecosystems := []ecosystemTypes.Ecosystem{}

	// osvReport, err := osvRepository.GetOSVReportForCVE(match.Vulnerability.NVDId)

	// if err != nil {
	// 	ecosystems = append(ecosystems, ecosystemTypes.OTHER)
	// } else {

	// 	for _, affectedRange := range osvReport.Affected {
	// 		if affectedRange.Package.Name == match.AffectedDependency.Name {

	// 			ecosystem := affectedRange.Package.Ecosystem

	// 			if ecosystem == "PyPI" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.PYTHON)
	// 			} else if ecosystem == "Maven" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.JAVA)
	// 			} else if ecosystem == "Android" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.JAVA)
	// 			} else if ecosystem == "npm" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
	// 			} else if ecosystem == "Packagist" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.PHP)
	// 			} else if ecosystem == "Go" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.GO)
	// 			} else if ecosystem == "RubyGems" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.RUBY)
	// 			} else if ecosystem == "crates.io" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.RUST)
	// 			} else if ecosystem == "NuGet" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.DOTNET)
	// 			} else if ecosystem == "Hex" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.ERLANG)
	// 			} else if ecosystem == "Linux" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.NATIVE_OR_OS)
	// 			} else if ecosystem == "OSS-Fuzz" {
	// 				ecosystems = append(ecosystems, ecosystemTypes.NATIVE_OR_OS)
	// 			} else if strings.Contains(ecosystem, "Debian") {
	// 				ecosystems = append(ecosystems, ecosystemTypes.NATIVE_OR_OS)
	// 			} else {
	// 				ecosystems = append(ecosystems, ecosystemTypes.OTHER)
	// 			}

	// 		}
	// 	}

	// }

	return ecosystems

}
