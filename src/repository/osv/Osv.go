package osv

import (
	"context"
	"encoding/json"
	"log"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/package-url/packageurl-go"
	"github.com/uptrace/bun"
)

// GetAllOSVReportsForPurl retrieves all OSV reports for a given package URL (purl).
// It queries both the standard OSV table and the FriendsOfPHP table for PHP packages.
// The function returns a slice of OSVItem, which represents the OSV reports, and an error if any.
func GetAllOSVReportsForPurl(purl string, knowledge *bun.DB) ([]knowledge_db.OSVItem, error) {
	matches := []knowledge_db.OSVItem{}

	// Handle nil knowledge database gracefully
	if knowledge == nil {
		return matches, nil
	}

	ctx := context.Background()

	// Query standard OSV table using parameterized JSONB containment query
	containmentValue, err := json.Marshal([]map[string]map[string]string{{"package": {"purl": purl}}})
	if err != nil {
		log.Printf("Error marshaling OSV containment value: %v", err)
		return matches, err
	}

	rows, err := knowledge.QueryContext(ctx, `
		SELECT DISTINCT "id", "osv_id", "schema_version", "modified", "published", "withdrawn", "aliases", "related", "summary", "details", "severity", "affected", "references", "credits", "database_specific", "cwes", "cve", vlai_score, vlai_confidence
		FROM osv
		WHERE ("affected" @> ?::jsonb)
	`, string(containmentValue))
	if err != nil {
		log.Printf("Error querying OSV table: %v", err)
		return matches, err
	}

	err = knowledge.ScanRows(ctx, rows, &matches)
	if err != nil {
		log.Printf("Error scanning OSV rows: %v", err)
		return matches, err
	}

	// Check if this is a PHP package and query FriendsOfPHP table
	purlObj, err := packageurl.FromString(purl)
	if err == nil && purlObj.Type == "composer" {
		friendsOfPHPMatches, err := getFriendsOfPHPReportsForPackage(purlObj.Name, purlObj.Namespace, knowledge)
		if err != nil {
			log.Printf("Error querying FriendsOfPHP: %v", err)
		} else {
			// Convert FriendsOfPHP advisories to OSVItem format and add to matches
			for _, advisory := range friendsOfPHPMatches {
				osvItem := convertFriendsOfPHPToOSV(advisory)
				matches = append(matches, osvItem)
			}
		}
	}

	return matches, nil
}

// getFriendsOfPHPReportsForPackage queries the friends_of_php table for a specific package
func getFriendsOfPHPReportsForPackage(name, namespace string, knowledge *bun.DB) ([]knowledge_db.FriendsOfPHPAdvisory, error) {
	var advisories []knowledge_db.FriendsOfPHPAdvisory

	// Handle nil knowledge database gracefully
	if knowledge == nil {
		return advisories, nil
	}

	ctx := context.Background()

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
		OSVId:      "FRIENDSOFPHP-" + advisory.AdvisoryId,
		Summary:    advisory.Title,
		Details:    advisory.Description,
		Aliases:    aliases,
		Published:  advisory.Published,
		Modified:   advisory.Modified,
		References: references,
		Affected:   affected,
		DatabaseSpecific: map[string]interface{}{
			"source":      "FriendsOfPHP",
			"advisory_id": advisory.AdvisoryId,
		},
	}
}
