package extensionAnalyzer

import (
	"errors"
	"testing"

	extensionMatcher "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/vulnerabilityMatcher/extensions"
	"github.com/uptrace/bun"
)

type failingMatcher struct{ err error }

func (m failingMatcher) MatchExtensionVulnerabilities(string, string, *bun.DB) ([]extensionMatcher.ExtensionVulnerabilityMatch, error) {
	return nil, m.err
}

func TestFailedExtensionLookupIsReported(t *testing.T) {
	cause := errors.New("i/o timeout")
	analyzer := &PHPExtensionAnalyzer{matcher: failingMatcher{err: cause}}

	_, err := analyzer.AnalyzeExtensionVulnerabilities(map[string]string{"curl": "8.0.0"}, &bun.DB{})

	if !errors.Is(err, cause) {
		t.Fatalf("err = %v, want the lookup error", err)
	}
}
