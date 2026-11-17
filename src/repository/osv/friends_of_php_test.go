package osv

import (
	"errors"
	"testing"

	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func osvRows(items ...knowledge_db.OSVItem) func() ([]knowledge_db.OSVItem, error) {
	return func() ([]knowledge_db.OSVItem, error) { return items, nil }
}

func TestFailedFriendsOfPHPLookupFailsTheComposerLookup(t *testing.T) {
	cause := errors.New("relation \"friends_of_php\" does not exist")

	reports, err := allReportsForPurl("pkg:composer/symfony/http-kernel", osvRows(knowledge_db.OSVItem{OSVId: "GHSA-aaaa-bbbb-cccc"}),
		func(string, string) ([]knowledge_db.FriendsOfPHPAdvisory, error) { return nil, cause })

	assert.ErrorIs(t, err, cause)
	assert.Nil(t, reports, "no partial OSV list is returned with the error")
}

func TestFriendsOfPHPIsOnlyReadForComposerPackages(t *testing.T) {
	called := false
	reports, err := allReportsForPurl("pkg:npm/left-pad", osvRows(knowledge_db.OSVItem{OSVId: "GHSA-aaaa-bbbb-cccc"}),
		func(string, string) ([]knowledge_db.FriendsOfPHPAdvisory, error) {
			called = true
			return nil, errors.New("unreachable")
		})

	require.NoError(t, err)
	assert.False(t, called)
	assert.Len(t, reports, 1)
}

func TestFriendsOfPHPAdvisoriesAreAddedForComposerPackages(t *testing.T) {
	var gotName, gotNamespace string
	reports, err := allReportsForPurl("pkg:composer/symfony/http-kernel", osvRows(),
		func(name, namespace string) ([]knowledge_db.FriendsOfPHPAdvisory, error) {
			gotName, gotNamespace = name, namespace
			return []knowledge_db.FriendsOfPHPAdvisory{{Title: "Header injection", CVE: "CVE-2024-0001", AdvisoryId: "symfony/http-kernel/CVE-2024-0001"}}, nil
		})

	require.NoError(t, err)
	assert.Equal(t, "http-kernel", gotName)
	assert.Equal(t, "symfony", gotNamespace)
	assert.Len(t, reports, 1)
}

func TestFailedOSVQuerySkipsFriendsOfPHP(t *testing.T) {
	cause := errors.New("i/o timeout")
	called := false

	_, err := allReportsForPurl("pkg:composer/symfony/http-kernel",
		func() ([]knowledge_db.OSVItem, error) { return nil, cause },
		func(string, string) ([]knowledge_db.FriendsOfPHPAdvisory, error) { called = true; return nil, nil })

	assert.ErrorIs(t, err, cause)
	assert.False(t, called)
}
