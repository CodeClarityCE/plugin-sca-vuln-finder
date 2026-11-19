package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/package-url/packageurl-go"
	"github.com/uptrace/bun"
)

// keepReports returns the reports keep accepts, in order.
func keepReports(reports []knowledge_db.OSVItem, keep func(knowledge_db.OSVItem) bool) []knowledge_db.OSVItem {
	kept := make([]knowledge_db.OSVItem, 0, len(reports))
	for _, report := range reports {
		if keep(report) {
			kept = append(kept, report)
		}
	}
	return kept
}

// FilterPublishedOnOrBefore drops OSV reports whose Published timestamp falls
// after the end of the asof day (the whole asof day stays in range). Reports
// with an empty or unparseable Published timestamp are kept, matching the
// semantics of the knowledge osv_asof mirror.
func FilterPublishedOnOrBefore(reports []knowledge_db.OSVItem, asof time.Time) []knowledge_db.OSVItem {
	return keepReports(reports, func(report knowledge_db.OSVItem) bool {
		return repository.KeepPublishedOnOrBefore(report.Published, asof)
	})
}

// FilterWithdrawn drops withdrawn advisories. With an as-of date, an advisory
// withdrawn after that date is kept, since it was still active then.
func FilterWithdrawn(reports []knowledge_db.OSVItem, asof *time.Time) []knowledge_db.OSVItem {
	return keepReports(reports, func(report knowledge_db.OSVItem) bool {
		return report.Withdrawn == "" || (asof != nil && !repository.KeepPublishedOnOrBefore(report.Withdrawn, *asof))
	})
}

// FilterRetired drops retired records, except those still active on the as-of date.
func FilterRetired(reports []knowledge_db.OSVItem, asof *time.Time) []knowledge_db.OSVItem {
	return keepReports(reports, func(report knowledge_db.OSVItem) bool {
		return repository.ActiveAsOf(report.RetiredAt, asof)
	})
}

// WithoutMalicious drops malicious package advisories.
func WithoutMalicious(reports []knowledge_db.OSVItem) []knowledge_db.OSVItem {
	return keepReports(reports, func(report knowledge_db.OSVItem) bool {
		return report.Kind != knowledge_db.AdvisoryKindMalicious
	})
}

// GetAllOSVReportsForPurl is GetAllOSVReportsForPurlContext without a deadline.
func GetAllOSVReportsForPurl(purl string, knowledge *bun.DB) ([]knowledge_db.OSVItem, error) {
	return GetAllOSVReportsForPurlContext(context.Background(), purl, knowledge)
}

// GetAllOSVReportsForPurlContext retrieves all OSV reports for a given package URL (purl).
// It queries both the standard OSV table and, for composer packages, the FriendsOfPHP table.
// A failed query in either table returns an error.
func GetAllOSVReportsForPurlContext(ctx context.Context, purl string, knowledge *bun.DB) ([]knowledge_db.OSVItem, error) {
	if knowledge == nil {
		return []knowledge_db.OSVItem{}, nil
	}
	return allReportsForPurl(purl,
		func() ([]knowledge_db.OSVItem, error) { return queryOSVReports(ctx, purl, knowledge) },
		func(name, namespace string) ([]knowledge_db.FriendsOfPHPAdvisory, error) {
			return getFriendsOfPHPReportsForPackage(ctx, name, namespace, knowledge)
		})
}

// allReportsForPurl joins the OSV reports with the FriendsOfPHP ones of a composer package.
func allReportsForPurl(
	purl string,
	osvReports func() ([]knowledge_db.OSVItem, error),
	friendsOfPHP func(name, namespace string) ([]knowledge_db.FriendsOfPHPAdvisory, error),
) ([]knowledge_db.OSVItem, error) {
	matches, err := osvReports()
	if err != nil {
		return nil, err
	}

	purlObj, err := packageurl.FromString(purl)
	if err == nil && purlObj.Type == "composer" {
		advisories, err := friendsOfPHP(purlObj.Name, purlObj.Namespace)
		if err != nil {
			return nil, fmt.Errorf("FriendsOfPHP lookup: %w", err)
		}
		for _, advisory := range advisories {
			matches = append(matches, convertFriendsOfPHPToOSV(advisory))
		}
	}
	return matches, nil
}

// queryOSVReports reads the OSV reports whose affected list names purl.
func queryOSVReports(ctx context.Context, purl string, knowledge *bun.DB) ([]knowledge_db.OSVItem, error) {
	matches := []knowledge_db.OSVItem{}
	containmentValue, err := json.Marshal([]map[string]map[string]string{{"package": {"purl": purl}}})
	if err != nil {
		return nil, err
	}

	rows, err := knowledge.QueryContext(ctx, `
		SELECT DISTINCT "id", "osv_id", "schema_version", "modified", "published", "withdrawn", "aliases", "related", "summary", "details", "severity", "affected", "references", "credits", "database_specific", "cwes", "cve", "kind", vlai_score, vlai_confidence, retired_reason, retired_at
		FROM osv
		WHERE ("affected" @> ?::jsonb)
	`, string(containmentValue))
	if err != nil {
		return nil, err
	}
	if err := knowledge.ScanRows(ctx, rows, &matches); err != nil {
		return nil, err
	}
	return matches, nil
}

// getFriendsOfPHPReportsForPackage queries the friends_of_php table for a specific package
func getFriendsOfPHPReportsForPackage(ctx context.Context, name, namespace string, knowledge *bun.DB) ([]knowledge_db.FriendsOfPHPAdvisory, error) {
	var advisories []knowledge_db.FriendsOfPHPAdvisory

	// Handle nil knowledge database gracefully
	if knowledge == nil {
		return advisories, nil
	}

	// Build the full package name
	var packageName string
	if namespace != "" {
		packageName = namespace + "/" + name
	} else {
		packageName = name
	}

	// Query FriendsOfPHP table
	err := knowledge.NewSelect().
		Model(&advisories).
		Where("composer = ?", packageName).
		Scan(ctx)

	if err != nil {
		return nil, err
	}

	return advisories, nil
}

// convertFriendsOfPHPToOSV converts a FriendsOfPHP advisory to OSVItem format
func convertFriendsOfPHPToOSV(advisory knowledge_db.FriendsOfPHPAdvisory) knowledge_db.OSVItem {
	// Extract affected versions from branches
	var affectedVersions []string
	for _, branch := range advisory.Branches {
		affectedVersions = append(affectedVersions, branch.Versions...)
	}

	// Create OSV affected entry
	affected := []knowledge_db.Affected{
		{
			Package: knowledge_db.OSVPackage{
				Ecosystem: "Packagist",
				Name:      advisory.Composer,
			},
			Versions: affectedVersions,
		},
	}

	// Create references
	references := []knowledge_db.Reference{
		{
			Type: "ADVISORY",
			Url:  advisory.Link,
		},
	}
	if advisory.Reference != "" {
		references = append(references, knowledge_db.Reference{
			Type: "WEB",
			Url:  advisory.Reference,
		})
	}

	// Set aliases (CVE if available)
	var aliases []string
	if advisory.CVE != "" {
		aliases = append(aliases, advisory.CVE)
	}

	return knowledge_db.OSVItem{
		Retirement: advisory.Retirement,
		OSVId:      "FRIENDSOFPHP-" + advisory.AdvisoryId,
		Summary:    advisory.Title,
		Details:    advisory.Description,
		Aliases:    aliases,
		Published:  advisory.Published,
		Modified:   advisory.Modified,
		References: references,
		Affected:   affected,
		DatabaseSpecific: map[string]any{
			"source":      "FriendsOfPHP",
			"advisory_id": advisory.AdvisoryId,
		},
	}
}

// GetByIDsContext reads every OSV record, withdrawn ones too, whose own ID, CVE or a CVE alias is in ids.
func GetByIDsContext(ctx context.Context, ids []string, knowledge *bun.DB) ([]knowledge_db.OSVItem, error) {
	records := []knowledge_db.OSVItem{}
	if knowledge == nil {
		return records, nil
	}
	seen := map[string]bool{}
	for chunk := range slices.Chunk(ids, byIDChunk) {
		found, err := getByIDs(ctx, chunk, knowledge)
		if err != nil {
			return nil, err
		}
		for _, record := range found {
			if !seen[record.OSVId] {
				seen[record.OSVId] = true
				records = append(records, record)
			}
		}
	}
	return records, nil
}

// byIDChunk caps the IDs of one query, which tests one alias containment per ID.
const byIDChunk = 200

func getByIDs(ctx context.Context, ids []string, knowledge *bun.DB) ([]knowledge_db.OSVItem, error) {
	records := []knowledge_db.OSVItem{}
	// One containment test per CVE alias, so the GIN index on cve_aliases is used.
	aliases := make([]string, 0, len(ids))
	for _, id := range ids {
		encoded, err := json.Marshal([]string{id})
		if err != nil {
			return nil, err
		}
		aliases = append(aliases, string(encoded))
	}
	err := knowledge.NewSelect().Model(&records).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			q = q.Where("osv_id IN (?)", bun.In(ids)).WhereOr("cve IN (?)", bun.In(ids))
			for _, alias := range aliases {
				q = q.WhereOr("cve_aliases @> ?::jsonb", alias)
			}
			return q
		}).
		Scan(ctx)
	return records, err
}
