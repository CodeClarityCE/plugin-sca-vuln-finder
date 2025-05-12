package advisory

import (
	"log"
	"net/url"
	"strings"

	"slices"

	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
)

// InferEcosystemAdvisoryUrlExtractor extracts the ecosystem types based on the advisory URLs in the given NVD vulnerability match.
// It returns a slice of ecosystem types.
func InferEcosystemAdvisoryUrlExtractor(match vulnerabilityFinder.NVDVulnerability) []ecosystemTypes.Ecosystem {

	ecosystems := []ecosystemTypes.Ecosystem{}

	for _, advisory := range match.Vulnerability.References {
		domain := getDomainOfAdvisory(advisory.Source)
		if slices.Contains(COMMON_JAVASCRIPT_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
		} else if slices.Contains(COMMON_NODE_ADVISORY_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
		} else if slices.Contains(COMMON_PHP_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.PHP)
		} else if slices.Contains(COMMON_PYTHON_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.PYTHON)
		} else if slices.Contains(COMMON_RUBY_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.RUBY)
		} else if slices.Contains(COMMON_RUST_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.RUST)
		} else if slices.Contains(COMMON_JAVA_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.JAVA)
		} else if slices.Contains(COMMON_SWIFT_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.SWIFT)
		} else if slices.Contains(COMMON_GO_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.GO)
		} else if slices.Contains(COMMON_PERL_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.PERL)
		} else if slices.Contains(COMMON_C_OR_C_PLUS_PLUS_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.C_OR_C_PLUS_PLUS)
		} else if slices.Contains(COMMON_NATIVE_OR_OS_ADVISORY_DOMAINS, domain) {
			ecosystems = append(ecosystems, ecosystemTypes.NATIVE_OR_OS)
		} else {
			ecosystems = append(ecosystems, ecosystemTypes.NONE)
		}
	}

	return ecosystems

}

// getDomainOfAdvisory extracts the domain from the given advisory URL.
// It parses the URL and returns the domain name without the "www" prefix.
// If the URL parsing fails, it logs an error and returns an empty string.
func getDomainOfAdvisory(advisoryUrl string) string {
	url, err := url.Parse(advisoryUrl)
	if err != nil {
		log.Printf("Failed to parse advisoryUrl: " + advisoryUrl)
		return ""
	}
	return strings.TrimPrefix(url.Hostname(), "www")
}
