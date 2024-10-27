package vulnerabilityFinder

import (
	semverVersionTypes "github.com/CodeClarityCE/utility-node-semver/versions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

type AffectedExact struct {
	VersionString string
	VersionSemver semverVersionTypes.Semver
	CPEInfo       knowledge.Sources
}

type AffectedUniversal struct {
	CPEInfo knowledge.Sources
}

// AffectedRange represents a vulnerable range of a library, denoting at which version the
// vulnerability was introduced and when (if at all) it was fixed
type AffectedRange struct {
	IntroducedSemver semverVersionTypes.Semver
	FixedSemver      semverVersionTypes.Semver
	CPEInfo          knowledge.Sources
}

// AffectedVersion encapsulates information on affected vulnerability ranges,
// exact vulnerable versions, and whether the "whole" of the library is affected
type AffectedVersion struct {
	Exact     []AffectedExact
	Ranges    []AffectedRange
	Universal AffectedUniversal
}

// VulnerableEvidenceRange encapsulates information "prooving" that a dependency is affected
// by an affected product range
type VulnerableEvidenceRange struct {
	Vulnerable AffectedRange
	Installed  semverVersionTypes.Semver
	OpenEnd    bool
}

// VulnerableEvidenceExact encapsulates information "prooving" that a dependency is affected
// by an affected product version
type VulnerableEvidenceExact struct {
	Vulnerable AffectedExact
	Installed  semverVersionTypes.Semver
}

// VulnerableEvidenceUniversal encapsulates information "prooving" that a dependency is affected
// by an affected product version
type VulnerableEvidenceUniversal struct {
	Vulnerable AffectedUniversal
	Installed  semverVersionTypes.Semver
}

type VulnerableEvidenceType string

const (
	VULNERABLE_EVIDENCE_EXACT     VulnerableEvidenceType = "VULNERABLE_EVIDENCE_EXACT"
	VULNERABLE_EVIDENCE_UNIVERSAL VulnerableEvidenceType = "VULNERABLE_EVIDENCE_UNIVERSAL"
	VULNERABLE_EVIDENCE_RANGE     VulnerableEvidenceType = "VULNERABLE_EVIDENCE_RANGE"
)

type NonVulnerableEvidenceType string

const (
	NONE_MATCHING_LESS_THAN_FIRST_VULNERABLE   NonVulnerableEvidenceType = "NONE_MATCHING_LESS_THAN_FIRST_VULNERABLE"
	NONE_MATCHING_GREATER_THAN_LAST_VULNERABLE NonVulnerableEvidenceType = "NONE_MATCHING_GREATER_THAN_LAST_VULNERABLE"
	NONE_MATCHING_IN_BETWEEN_VULNERABLE_RANGES NonVulnerableEvidenceType = "NONE_MATCHING_IN_BETWEEN_VULNERABLE_RANGES"
)

// A non-vulnerable evidence clase for maintaining evidence data that a dependency is not vulnerable to a specific vulnerability.
//
// - Type: `NONE_MATCHING_LESS_THAN_FIRST_VULNERABLE`
//
// ```
//
//	"ClosestKnownUnpatchedIntroduction": "4.0.0",
//	"ClosestKnownPatchedVersion": "4.1.2",
//	"NextKnownUnpatchedVersion": "4.0.0",
//	"Installed": "3.3.6",
//	"Type": "NONE_MATCHING_LESS_THAN_FIRST_VULNERABLE"
//
// ```
//
// - Type: `NONE_MATCHING_GREATER_THAN_LAST_VULNERABLE`
//
// ```
//
//	"ClosestKnownUnpatchedIntroduction": "4.0.0",
//	"ClosestKnownPatchedVersion": "4.1.2",
//	"NextKnownUnpatchedVersion": nil,
//	"Installed": "4.3.6",
//	"Type": "NONE_MATCHING_GREATER_THAN_LAST_VULNERABLE"
//
// ```
//
// - Type: `NONE_MATCHING_IN_BETWEEN_VULNERABLE_RANGES`
//
// ```
//
//	"ClosestKnownUnpatchedIntroduction": "4.0.0",
//	"ClosestKnownPatchedVersion": "4.1.2",
//	"NextKnownUnpatchedVersion": "4.7.5",
//	"Installed": "4.3.6",
//	"Type": "NONE_MATCHING_IN_BETWEEN_VULNERABLE_RANGES"
//
// ```
type NonVulnerableEvidence struct {
	ClosestKnownUnpatchedIntroduction semverVersionTypes.Semver
	ClosestKnownPatchedVersion        semverVersionTypes.Semver
	NextKnownUnpatchedVersion         semverVersionTypes.Semver
	Installed                         semverVersionTypes.Semver
	Type                              NonVulnerableEvidenceType
}
