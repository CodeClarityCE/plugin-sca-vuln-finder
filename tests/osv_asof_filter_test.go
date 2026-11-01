package main

import (
	"testing"
	"time"

	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository"
	osvRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/osv"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
)

// TestFilterPublishedOnOrBefore checks the knowledge as-of cutoff semantics:
// the whole as-of day stays in range, later publications are dropped, and
// advisories with an empty or unparseable published timestamp are kept.
func TestFilterPublishedOnOrBefore(t *testing.T) {
	asof := time.Date(2023, 6, 15, 0, 0, 0, 0, time.UTC)

	reports := []knowledge_db.OSVItem{
		{OSVId: "OSV-BEFORE", Published: "2023-06-01T12:00:00Z"},
		{OSVId: "OSV-ON-ASOF-DAY", Published: "2023-06-15T23:59:59Z"},
		{OSVId: "OSV-AFTER", Published: "2023-06-16T00:00:00Z"},
		{OSVId: "OSV-EMPTY", Published: ""},
		{OSVId: "OSV-UNPARSEABLE", Published: "not-a-timestamp"},
	}

	filtered := osvRepository.FilterPublishedOnOrBefore(reports, asof)

	keptIds := []string{}
	for _, report := range filtered {
		keptIds = append(keptIds, report.OSVId)
	}

	assert.Equal(t, []string{"OSV-BEFORE", "OSV-ON-ASOF-DAY", "OSV-EMPTY", "OSV-UNPARSEABLE"}, keptIds)
	assert.NotContains(t, keptIds, "OSV-AFTER")
}

// TestKeepPublishedOnOrBefore covers the lenient timestamp parsing shared by
// the OSV/NVD/GCVE as-of filters: the knowledge sources mix RFC3339,
// zone-less fractional (NVD/GCVE style), and bare-date formats.
func TestKeepPublishedOnOrBefore(t *testing.T) {
	asof := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	kept := []string{
		"2022-12-31T23:59:59Z",    // RFC3339 before cutoff
		"2023-01-01T23:59:59Z",    // on the asof day (whole day in range)
		"2023-01-01T12:00:00.500", // zone-less fractional, on the asof day
		"2022-06-15",              // bare date before cutoff
		"",                        // empty -> kept
		"not-a-timestamp",         // unparseable -> kept
	}
	dropped := []string{
		"2023-01-02T00:00:00Z",    // RFC3339 just past the asof day
		"2024-03-01T07:30:26.981", // zone-less fractional (NVD style) after
		"2026-07-29T13:32:01.534Z",
		"2023-01-02", // bare date after
	}

	for _, published := range kept {
		assert.True(t, repository.KeepPublishedOnOrBefore(published, asof), "expected %q to be kept", published)
	}
	for _, published := range dropped {
		assert.False(t, repository.KeepPublishedOnOrBefore(published, asof), "expected %q to be dropped", published)
	}
}
