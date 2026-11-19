package vulnerabilityFinder

import (
	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types/conflict"
	semverVersionTypes "github.com/CodeClarityCE/utility-node-semver/versions"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

type VulnerabilitySource string

const (
	NVD              VulnerabilitySource = "NVD"
	OSV              VulnerabilitySource = "OSV"
	FriendsOfPHP     VulnerabilitySource = "FriendsOfPHP"
	GCVE             VulnerabilitySource = "GCVE"
	PRIVATE_ANALYSIS VulnerabilitySource = "PRIVATE_ANALYSIS"
)

type SeverityType string

const (
	CVSS_V2  SeverityType = "CVSS_V2"
	CVSS_V3  SeverityType = "CVSS_V3"
	CVSS_V31 SeverityType = "CVSS_V31"
	CVSS_V40 SeverityType = "CVSS_V40"
	// GHSA_SEVERITY is GHSA's qualitative label, used when a record has no vector; it has no score.
	GHSA_SEVERITY SeverityType = "GHSA"
)

type VulnerabilityMatchSeverity struct {
	SeverityClass                  CVSS_CLASSV3
	Severity                       float64
	SeverityType                   SeverityType
	Vector                         string
	Impact                         float64
	Exploitability                 float64
	ConfidentialityImpact          string
	IntegrityImpact                string
	AvailabilityImpact             string
	ConfidentialityImpactNumerical float32
	IntegrityImpactNumerical       float32
	AvailabilityImpactNumerical    float32
	// Vectors holds every CVSS vector of the shown record, the shown one included.
	Vectors []SourceSeverity `json:"Vectors,omitempty"`
}

type WinningSource string

const (
	WINNER_NVD     WinningSource = "NVD"
	WINNER_OSV     WinningSource = "OSV"
	WINNER_GCVE    WinningSource = "GCVE"
	WINNER_NEITHER WinningSource = "NEITHER"
)

type AffectedInfo struct {
	Exact     []string
	Ranges    []AffectedRange
	Universal bool
}

type VulnerabilityMatch struct {
	Affected           map[string]AffectedInfo
	WinningSource      WinningSource
	Id                 uint64
	Sources            []VulnerabilitySource
	AffectedDependency string
	Vulnerability      string
	Severity           VulnerabilityMatchSeverity
	Weaknesses         []VulnerabilityMatchWeakness
}

type VulnerabilityMatchWeakness struct {
	WeaknessId     string
	OWASPTop10Id   string
	OWASPTop10Name string
}

type WorkSpaceVulnerabilities []VulnerabilityMatch

type DependencyInfoVuln struct {
	Vulnerability string
	Severity      VulnerabilityMatchSeverity
	Weaknesses    []VulnerabilityMatchWeakness
}

type DependencyInfo struct {
	SeverityDist    sbom.SeverityDist
	Vulnerable      bool
	Vulnerabilities []DependencyInfoVuln
}
type Workspace struct {
	Vulnerabilities []Vulnerability
	// Packages reported as intentionally harmful. Absent on older analyses and when there are none.
	MaliciousPackageAdvisories []MaliciousPackageAdvisory `json:"MaliciousPackageAdvisories,omitempty"`
}

// MaliciousPackageAdvisory says an installed package version is intentionally harmful.
// It has no severity or EPSS score and is not counted as a vulnerability.
type MaliciousPackageAdvisory struct {
	AdvisoryId         string
	AffectedDependency string
	AffectedVersion    string
	DirectDependency   bool
	Summary            string   `json:"Summary,omitempty"`
	Details            string   `json:"Details,omitempty"`
	Published          string   `json:"Published,omitempty"`
	Modified           string   `json:"Modified,omitempty"`
	Aliases            []string `json:"Aliases,omitempty"`
	References         []string `json:"References,omitempty"`
}

type Output struct {
	WorkSpaces   map[string]Workspace `json:"workspaces"`
	AnalysisInfo AnalysisInfo         `json:"analysis_info"`
}

type AnalysisStatVulnerabilitySeverityDist struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	None     int `json:"none"`
}

type AnalysisStats struct {
	NumberOfVulnerableDependencies   int                                   `json:"number_of_vulnerable_dependencies"`
	NumberOfVulnerabilities          int                                   `json:"number_of_vulnerabilities"`
	NumberOfTransitiveVulnerabilites int                                   `json:"number_of_transitive_vulnerabilites"`
	NumberOfDirectVulnerabilities    int                                   `json:"number_of_direct_vulnerabilities"`
	MeanSeverity                     float64                               `json:"mean_severity"`
	MaxSeverity                      float64                               `json:"max_severity"`
	SeverityDist                     AnalysisStatVulnerabilitySeverityDist `json:"severity_dist"`
}

type AnalysisInfo struct {
	Status                   codeclarity.AnalysisStatus `json:"status"`
	Errors                   []exceptions.Error         `json:"errors"`
	AnalysisStartTime        string                     `json:"analysis_start_time"`
	AnalysisEndTime          string                     `json:"analysis_end_time"`
	AnalysisDeltaTime        float64                    `json:"analysis_delta_time"`
	VersionSeperator         string                     `json:"version_seperator"`
	ImportPathSeperator      string                     `json:"import_path_seperator"`
	DefaultWorkspaceName     string                     `json:"default_workspace_name"`
	SelfManagedWorkspaceName string                     `json:"self_managed_workspace_name"`
	// KnowledgeSnapshot is every knowledge source's state when the analysis ran. Absent on older analyses.
	KnowledgeSnapshot *knowledge.KnowledgeSnapshot `json:"knowledge_snapshot,omitempty"`
}

type CVSS_CLASSV3 string

const (
	CRITICAL CVSS_CLASSV3 = "CRITICAL"
	HIGH     CVSS_CLASSV3 = "HIGH"
	MEDIUM   CVSS_CLASSV3 = "MEDIUM"
	LOW      CVSS_CLASSV3 = "LOW"
	NONE     CVSS_CLASSV3 = "NONE"
)

type Dependency struct {
	Name        string
	VersionInfo sbom.Versions
	Semver      semverVersionTypes.Semver
}

type NVDVulnerability struct {
	Vulnerability               knowledge.NVDItem
	Dependency                  Dependency
	AffectedInfo                []AffectedVersion
	VulnerableEvidenceRange     VulnerableEvidenceRange
	VulnerableEvidenceExact     VulnerableEvidenceExact
	VulnerableEvidenceUniversal VulnerableEvidenceUniversal
	VulnerableEvidenceType      VulnerableEvidenceType
	Vulnerable                  bool
	ConflictFlag                conflict.ConflictFlag
	Severity                    float64
	SeverityType                SeverityType
}

type OSVVulnerability struct {
	Vulnerability               knowledge.OSVItem
	Dependency                  Dependency
	AffectedInfo                []AffectedVersion
	VulnerableEvidenceRange     VulnerableEvidenceRange
	VulnerableEvidenceExact     VulnerableEvidenceExact
	VulnerableEvidenceUniversal VulnerableEvidenceUniversal
	VulnerableEvidenceType      VulnerableEvidenceType
	Vulnerable                  bool
	ConflictFlag                conflict.ConflictFlag
	Severity                    float64
	SeverityType                SeverityType
}

type GCVEVulnerability struct {
	Vulnerability               knowledge.GCVEItem
	Dependency                  Dependency
	AffectedInfo                []AffectedVersion
	VulnerableEvidenceRange     VulnerableEvidenceRange
	VulnerableEvidenceExact     VulnerableEvidenceExact
	VulnerableEvidenceUniversal VulnerableEvidenceUniversal
	VulnerableEvidenceType      VulnerableEvidenceType
	Vulnerable                  bool
	ConflictFlag                conflict.ConflictFlag
	Severity                    float64
	SeverityType                SeverityType
}

// EPSS is a plugin-local copy of the knowledge DB exploit-prediction row: the
// shared knowledge.EPSS struct tags Score/Percentile with lowercase JSON keys,
// while the plugin output must expose them as "Score"/"Percentile".
type EPSS struct {
	Score      float32
	Percentile float32
}

type Vulnerability struct {
	Sources            []VulnerabilitySource
	AffectedDependency string
	AffectedVersion    string
	VulnerabilityId    string
	OSVMatch           *OSVVulnerability  `json:"OSVMatch,omitempty"`
	NVDMatch           *NVDVulnerability  `json:"NVDMatch,omitempty"`
	GCVEMatch          *GCVEVulnerability `json:"GCVEMatch,omitempty"`
	// Matches from the same source for this vulnerability and dependency that are not shown.
	AdditionalOSVMatches  []OSVVulnerability  `json:"AdditionalOSVMatches,omitempty"`
	AdditionalNVDMatches  []NVDVulnerability  `json:"AdditionalNVDMatches,omitempty"`
	AdditionalGCVEMatches []GCVEVulnerability `json:"AdditionalGCVEMatches,omitempty"`
	// Every source match for this vulnerability and dependency, kept for comparing sources. Absent on older analyses.
	SourceMatches []SourceMatch `json:"SourceMatches,omitempty"`
	// What each knowledge source said about this dependency version. Absent on older analyses.
	SourceVerdicts []SourceVerdict `json:"SourceVerdicts,omitempty"`
	// Ecosystem is the dependency's OSV ecosystem, like "npm" or "Packagist". Absent on older analyses.
	Ecosystem  string `json:"Ecosystem,omitempty"`
	Severity   VulnerabilityMatchSeverity
	EPSS       *EPSS `json:"EPSS,omitempty"`
	Weaknesses []VulnerabilityMatchWeakness
	Conflict   Conflict
	// Extension-related fields for PHP extension vulnerabilities
	PackageName      string   `json:"package_name,omitempty"`
	CurrentVersion   string   `json:"current_version,omitempty"`
	Constraint       string   `json:"constraint,omitempty"`
	DirectDependency bool     `json:"direct_dependency,omitempty"`
	Source           string   `json:"source,omitempty"`
	CVSS             float64  `json:"cvss,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	Details          string   `json:"details,omitempty"`
	References       []string `json:"references,omitempty"`
	PublishedDate    string   `json:"published_date,omitempty"`
	ModifiedDate     string   `json:"modified_date,omitempty"`
	WithdrawnDate    string   `json:"withdrawn_date,omitempty"`
	ExtensionType    string   `json:"extension_type,omitempty"` // "php-extension" for PHP extensions

	// Disputed is true when a matched CVE record says its vendor disputes it.
	Disputed bool `json:"Disputed,omitempty"`
}

// SourceMatch is one knowledge source's claim that a vulnerability affects a dependency version.
type SourceMatch struct {
	// Source is the knowledge source name, such as "osv", "nvd", "gcve" or "friends_of_php".
	Source   string `json:"source"`
	RecordId string `json:"record_id"`
	// Winning is true for the one match shown to users.
	Winning  bool                   `json:"winning"`
	Affected SourceAffected         `json:"affected"`
	Evidence VulnerableEvidenceType `json:"evidence"`
	// Severity is nil when the source gives no usable CVSS score.
	Severity *SourceSeverity `json:"severity"`
	// Vectors holds every CVSS vector of the record.
	Vectors   []SourceSeverity `json:"vectors,omitempty"`
	Published string           `json:"published,omitempty"`
	Modified  string           `json:"modified,omitempty"`
}

// Verdict is what one knowledge source said about a vulnerability instance.
type Verdict string

const (
	VerdictMatched Verdict = "matched"
	// VerdictNoRecord means the source was healthy and had no matching record.
	VerdictNoRecord Verdict = "no_record"
	// VerdictStaleOrFailed means the source had no match while stale, failed or of unknown state.
	VerdictStaleOrFailed Verdict = "stale_or_failed"
	// VerdictVersionExcluded means a record for the package leaves the installed version out.
	VerdictVersionExcluded Verdict = "version_excluded"
	// VerdictRetired means the record was rejected, withdrawn or removed.
	VerdictRetired Verdict = "retired"
	// VerdictNamesAnotherProduct means the record of this vulnerability names a different product or package.
	VerdictNamesAnotherProduct Verdict = "names_another_product"
	// VerdictNoPackageData means the record names no package, like an unreviewed advisory,
	// or names it with no version data that can be read.
	VerdictNoPackageData Verdict = "no_package_data"
)

// SourceVerdict is one knowledge source's verdict on a vulnerability instance.
type SourceVerdict struct {
	// Source is a knowledge source name: "osv", "nvd" or "gcve".
	Source   string                 `json:"source"`
	Verdict  Verdict                `json:"verdict"`
	Evidence *SourceVerdictEvidence `json:"evidence,omitempty"`
}

// SourceVerdictEvidence says what a verdict rests on; fields unused by a verdict stay empty.
// The JSON names are stored in results and exported, so keep them stable.
type SourceVerdictEvidence struct {
	// RecordIds are the records the verdict rests on, for every verdict but no record and stale or failed.
	RecordIds []string `json:"record_ids,omitempty"`
	// SourceStatus is the source's sync state ("stale", "failed" or "unknown"), for a stale or failed verdict.
	SourceStatus string `json:"source_status,omitempty"`
	// Evaluated is the affected ranges and versions checked against the installed version, for version excluded.
	Evaluated *SourceAffected `json:"evaluated,omitempty"`
	// Unaffected is the GCVE "unaffected" entry that covers the installed version, for version excluded.
	Unaffected *SourceAffected `json:"unaffected,omitempty"`
	// RetiredReason is "rejected", "withdrawn" or "removed", for retired.
	RetiredReason string `json:"retired_reason,omitempty"`
	// RetiredAt is when the record was retired (RFC 3339), for retired; empty when the source gives no date.
	RetiredAt string `json:"retired_at,omitempty"`
	// Names are the products or packages the record names, for names another product.
	Names []SourceProduct `json:"names,omitempty"`
}

// SourceProduct is a product or package a record names; fields a source does not use stay empty.
type SourceProduct struct {
	// Ecosystem is the OSV ecosystem of the name, like "npm"; empty when the record gives none.
	Ecosystem string `json:"ecosystem,omitempty"`
	// Package names an OSV package, like "left-pad".
	Package string `json:"package,omitempty"`
	// Vendor and Product name a GCVE affected entry or an NVD CPE.
	Vendor  string `json:"vendor,omitempty"`
	Product string `json:"product,omitempty"`
	// TargetSw is an NVD CPE's target software, like "node.js" or "wordpress".
	TargetSw string `json:"target_sw,omitempty"`
}

// SourceAffected is the affected versions one source gives for the dependency.
type SourceAffected struct {
	Ranges    []SourceRange `json:"ranges"`
	Exact     []string      `json:"exact"`
	Universal bool          `json:"universal"`
}

// SourceRange is introduced <= version < fixed; an empty bound is open.
type SourceRange struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// SourceSeverity is the CVSS score one source gives; a GHSA label has a class and a zero score.
type SourceSeverity struct {
	Score  float64      `json:"score"`
	Type   SeverityType `json:"type"`
	Vector string       `json:"vector"`
	Class  CVSS_CLASSV3 `json:"class"`
}

type Conflict struct {
	ConflictWinner conflict.ResolveWinner
	ConflictFlag   conflict.ConflictFlag
}

// Pairs holds what each knowledge source says about one vulnerability and dependency.
// NVD, OSV and GCVE are the matches shown; the slices hold every match, shown one first.
type Pairs struct {
	NVD            NVDVulnerability
	OSV            OSVVulnerability
	GCVE           GCVEVulnerability
	NVDMatches     []NVDVulnerability
	OSVMatches     []OSVVulnerability
	GCVEMatches    []GCVEVulnerability
	ConflictWinner conflict.ResolveWinner
	ConflictFlag   conflict.ConflictFlag
}

func ConvertOutputToMap(output Output) map[string]any {
	result := make(map[string]any)
	result["workspaces"] = output.WorkSpaces
	result["analysis_info"] = output.AnalysisInfo
	return result
}
