package cpe

import (
	ecosystemTypes "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/ecosystemAnalyzer/types"
	vulnerabilityFinder "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"golang.org/x/exp/slices"
)

// InferEcosystemCpeTarget infers the ecosystem based on the given NVD vulnerability match.
// It analyzes the CPE information of the match and determines the corresponding ecosystem.
// The function returns a slice of ecosystemTypes.Ecosystem representing the inferred ecosystems.
func InferEcosystemCpeTarget(match vulnerabilityFinder.NVDVulnerability) []ecosystemTypes.Ecosystem {

	ecosystems := []ecosystemTypes.Ecosystem{}

	var cpeInfo knowledge.Sources

	if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE {
		cpeInfo = match.VulnerableEvidenceRange.Vulnerable.CPEInfo
	} else if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_EXACT {
		cpeInfo = match.VulnerableEvidenceExact.Vulnerable.CPEInfo
	} else if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_UNIVERSAL {
		cpeInfo = match.VulnerableEvidenceUniversal.Vulnerable.CPEInfo
	}

	targetSw := cpeInfo.CriteriaDict.TargetSw

	if slices.Contains(COMMON_JAVASCRIPT_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
	} else if slices.Contains(COMMON_NODE_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
	} else if slices.Contains(COMMON_PHP_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.PHP)
	} else if slices.Contains(COMMON_PYTHON_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.PYTHON)
	} else if slices.Contains(COMMON_RUBY_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.RUBY)
	} else if slices.Contains(COMMON_RUST_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.RUST)
	} else if slices.Contains(COMMON_JAVA_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.JAVA)
	} else if slices.Contains(COMMON_SWIFT_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.SWIFT)
	} else if slices.Contains(COMMON_GO_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.GO)
	} else if slices.Contains(COMMON_PERL_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.PERL)
	} else if slices.Contains(COMMON_C_OR_C_PLUS_PLUS_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.C_OR_C_PLUS_PLUS)
	} else if slices.Contains(COMMON_NATIVE_OR_OS_TARGET_SW, targetSw) {
		ecosystems = append(ecosystems, ecosystemTypes.NATIVE_OR_OS)
	} else {
		ecosystems = append(ecosystems, ecosystemTypes.NONE)
	}

	return ecosystems
}

// InferEcosystemCpeProduct infers the ecosystem based on the CPE (Common Platform Enumeration) information
// provided in the NVD (National Vulnerability Database) vulnerability match.
// It returns a list of ecosystem types that are associated with the CPE product.
func InferEcosystemCpeProduct(match vulnerabilityFinder.NVDVulnerability) []ecosystemTypes.Ecosystem {

	ecosystems := []ecosystemTypes.Ecosystem{}

	var cpeInfo knowledge.Sources

	if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE {
		cpeInfo = match.VulnerableEvidenceRange.Vulnerable.CPEInfo
	} else if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_EXACT {
		cpeInfo = match.VulnerableEvidenceExact.Vulnerable.CPEInfo
	} else if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_UNIVERSAL {
		cpeInfo = match.VulnerableEvidenceUniversal.Vulnerable.CPEInfo
	}

	product := cpeInfo.CriteriaDict.Product

	if slices.Contains(COMMON_JAVASCRIPT_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
	} else if slices.Contains(COMMON_NODE_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
	} else if slices.Contains(COMMON_PHP_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.PHP)
	} else if slices.Contains(COMMON_PYTHON_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.PYTHON)
	} else if slices.Contains(COMMON_RUBY_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.RUBY)
	} else if slices.Contains(COMMON_RUST_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.RUST)
	} else if slices.Contains(COMMON_JAVA_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.JAVA)
	} else if slices.Contains(COMMON_SWIFT_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.SWIFT)
	} else if slices.Contains(COMMON_GO_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.GO)
	} else if slices.Contains(COMMON_PERL_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.PERL)
	} else if slices.Contains(COMMON_C_OR_C_PLUS_PLUS_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.C_OR_C_PLUS_PLUS)
	} else if slices.Contains(COMMON_NATIVE_OR_OS_PRODUCT, product) {
		ecosystems = append(ecosystems, ecosystemTypes.NATIVE_OR_OS)
	} else {
		ecosystems = append(ecosystems, ecosystemTypes.NONE)
	}

	return ecosystems
}

// InferEcosystemCpeVendor infers the ecosystem based on the CPE vendor information in the given NVD vulnerability match.
// It returns a list of ecosystem types that are associated with the inferred vendor.
func InferEcosystemCpeVendor(match vulnerabilityFinder.NVDVulnerability) []ecosystemTypes.Ecosystem {

	ecosystems := []ecosystemTypes.Ecosystem{}

	var cpeInfo knowledge.Sources

	if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_RANGE {
		cpeInfo = match.VulnerableEvidenceRange.Vulnerable.CPEInfo
	} else if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_EXACT {
		cpeInfo = match.VulnerableEvidenceExact.Vulnerable.CPEInfo
	} else if match.VulnerableEvidenceType == vulnerabilityFinder.VULNERABLE_EVIDENCE_UNIVERSAL {
		cpeInfo = match.VulnerableEvidenceUniversal.Vulnerable.CPEInfo
	}

	vendor := cpeInfo.CriteriaDict.Vendor

	if slices.Contains(COMMON_JAVASCRIPT_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
	} else if slices.Contains(COMMON_NODE_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.NODEJS_OR_JS)
	} else if slices.Contains(COMMON_PHP_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.PHP)
	} else if slices.Contains(COMMON_PYTHON_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.PYTHON)
	} else if slices.Contains(COMMON_RUBY_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.RUBY)
	} else if slices.Contains(COMMON_RUST_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.RUST)
	} else if slices.Contains(COMMON_JAVA_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.JAVA)
	} else if slices.Contains(COMMON_SWIFT_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.SWIFT)
	} else if slices.Contains(COMMON_GO_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.GO)
	} else if slices.Contains(COMMON_PERL_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.PERL)
	} else if slices.Contains(COMMON_C_OR_C_PLUS_PLUS_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.C_OR_C_PLUS_PLUS)
	} else if slices.Contains(COMMON_NATIVE_OR_OS_VENDOR, vendor) {
		ecosystems = append(ecosystems, ecosystemTypes.NATIVE_OR_OS)
	} else {
		ecosystems = append(ecosystems, ecosystemTypes.NONE)
	}

	return ecosystems
}
