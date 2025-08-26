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
	PRIVATE_ANALYSIS VulnerabilitySource = "PRIVATE_ANALYSIS"
)

type SeverityType string

const (
	CVSS_V2  SeverityType = "CVSS_V2"
	CVSS_V3  SeverityType = "CVSS_V3"
	CVSS_V31 SeverityType = "CVSS_V31"
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
}

type WinningSource string

const (
	WINNER_NVD     WinningSource = "NVD"
	WINNER_OSV     WinningSource = "OSV"
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

type Vulnerability struct {
	Sources            []VulnerabilitySource
	AffectedDependency string
	AffectedVersion    string
	VulnerabilityId    string
	OSVMatch           *OSVVulnerability `json:"OSVMatch,omitempty"`
	NVDMatch           *NVDVulnerability `json:"NVDMatch,omitempty"`
	Severity           VulnerabilityMatchSeverity
	Weaknesses         []VulnerabilityMatchWeakness
	Conflict           Conflict
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
}

type Conflict struct {
	ConflictWinner conflict.ResolveWinner
	ConflictFlag   conflict.ConflictFlag
}

type Pairs struct {
	NVD            NVDVulnerability
	OSV            OSVVulnerability
	ConflictWinner conflict.ResolveWinner
	ConflictFlag   conflict.ConflictFlag
}

func ConvertOutputToMap(output Output) map[string]interface{} {
	result := make(map[string]interface{})
	result["workspaces"] = output.WorkSpaces
	result["analysis_info"] = output.AnalysisInfo
	return result
}
