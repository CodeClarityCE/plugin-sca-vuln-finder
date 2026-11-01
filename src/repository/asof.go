package repository

import "time"

// publishedLayouts are the timestamp formats observed across the knowledge
// sources' published columns: RFC3339 (OSV, GCVE), zone-less with optional
// fractional seconds (NVD, some GCVE rows), and bare dates. Zone-less values
// are treated as UTC.
var publishedLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02",
}

// KeepPublishedOnOrBefore reports whether an advisory with the given published
// timestamp survives a knowledge as-of cutoff: true when it was published on
// or before the end of the asof day (the whole asof day stays in range).
// Empty or unparseable timestamps are kept, matching the semantics of the
// knowledge service's osv_asof mirror — a missing date must not silently
// erase an advisory.
func KeepPublishedOnOrBefore(published string, asof time.Time) bool {
	if published == "" {
		return true
	}
	cutoff := asof.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	for _, layout := range publishedLayouts {
		if ts, err := time.Parse(layout, published); err == nil {
			return ts.Before(cutoff)
		}
	}
	return true
}
