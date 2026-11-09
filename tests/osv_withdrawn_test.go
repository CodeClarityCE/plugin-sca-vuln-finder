package main

import (
	"testing"
	"time"

	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/osv"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
)

func withdrawnFixture() []knowledge_db.OSVItem {
	return []knowledge_db.OSVItem{
		{OSVId: "ACTIVE"},
		{OSVId: "WITHDRAWN", Withdrawn: "2025-12-02T15:11:19Z"},
	}
}

func ids(reports []knowledge_db.OSVItem) []string {
	out := []string{}
	for _, report := range reports {
		out = append(out, report.OSVId)
	}
	return out
}

func TestFilterWithdrawnDropsWithdrawnAdvisories(t *testing.T) {
	got := ids(osv.FilterWithdrawn(withdrawnFixture(), nil))
	if len(got) != 1 || got[0] != "ACTIVE" {
		t.Errorf("got %v, want only ACTIVE", got)
	}
}

func TestFilterWithdrawnKeepsAdvisoryWithdrawnAfterAsOf(t *testing.T) {
	asof := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	if got := osv.FilterWithdrawn(withdrawnFixture(), &asof); len(got) != 2 {
		t.Errorf("got %v, want both advisories", ids(got))
	}
}

func TestFilterWithdrawnDropsAdvisoryWithdrawnBeforeAsOf(t *testing.T) {
	asof := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := ids(osv.FilterWithdrawn(withdrawnFixture(), &asof))
	if len(got) != 1 || got[0] != "ACTIVE" {
		t.Errorf("got %v, want only ACTIVE", got)
	}
}

func retiredFixture() []knowledge_db.OSVItem {
	active := knowledge_db.OSVItem{OSVId: "ACTIVE"}
	retired := knowledge_db.OSVItem{OSVId: "RETIRED"}
	retired.RetiredReason = knowledge_db.RetiredRemoved
	retired.RetiredAt = time.Date(2025, 12, 2, 15, 0, 0, 0, time.UTC)
	return []knowledge_db.OSVItem{active, retired}
}

func TestFilterRetiredDropsRetiredRecordsByDefault(t *testing.T) {
	got := ids(osv.FilterRetired(retiredFixture(), nil))
	if len(got) != 1 || got[0] != "ACTIVE" {
		t.Errorf("got %v, want only ACTIVE", got)
	}
}

func TestFilterRetiredKeepsRecordBeforeItsRetirementDate(t *testing.T) {
	asof := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	if got := osv.FilterRetired(retiredFixture(), &asof); len(got) != 2 {
		t.Errorf("got %v, want both", ids(got))
	}
}

func TestFilterRetiredDropsRecordAfterItsRetirementDate(t *testing.T) {
	asof := time.Date(2025, 12, 2, 0, 0, 0, 0, time.UTC)
	if got := osv.FilterRetired(retiredFixture(), &asof); len(got) != 1 {
		t.Errorf("got %v, want only ACTIVE on the retirement day", ids(got))
	}
}
