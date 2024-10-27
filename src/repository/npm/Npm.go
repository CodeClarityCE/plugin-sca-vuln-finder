package npm

import (
	"context"
	"fmt"
	"log"
	"sort"

	packageRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository"
	"github.com/CodeClarityCE/service-knowledge/src/mirrors/js"
	nodesemver "github.com/CodeClarityCE/utility-node-semver"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var NpmPackageRepository = packageRepository.PackageRepository{
	GetVersionStrings:      GetVersionStrings,
	GetVersionStringsBelow: GetVersionStringsBelow,
	GetVersionStringsAbove: GetVersionStringsAbove,
	GetFirstVersionString:  GetFirstVersionString,
	GetLastVersionString:   GetLastVersionString,
}

// GetVersionStrings retrieves the version strings of a given dependency.
// It first checks if the version strings are already cached in the dependencyVersionsCache.
// If not, it queries the database to fetch the version strings and stores them in the cache for future use.
// The dependency name can be in the format "owner/repo" or "owner:repo".
// It returns the version strings in ascending order and an error if any.
func GetVersionStrings(depName string, knowledge *bun.DB) ([]string, error) {
	versions := []string{}
	dependency := knowledge_db.Package{}
	ctx := context.Background()
	exists, err := knowledge.NewSelect().Model(&dependency).Relation("Versions").Where("name = ?", depName).Exists(ctx)
	if err != nil {
		return nil, err
	}
	if !exists {
		err = js.UpdatePackage(knowledge, depName)
		if err != nil {
			return nil, err
		}
	}

	err = knowledge.NewSelect().Model(&dependency).Relation("Versions").Where("name = ?", depName).Scan(ctx)
	if err != nil {
		return nil, err
	}

	for _, version := range dependency.Versions {
		versions = append(versions, version.Version)
	}

	sortSemvers(versions)

	return versions, nil

}

// GetVersionStringsBelow returns a list of version strings below a given dependency version.
// It takes the dependency name, dependency version, and limit as input parameters.
// It returns a slice of version strings that satisfy the constraint "< depVersion" and are available for the given dependency name.
// The limit parameter specifies the maximum number of version strings to be returned.
// If an error occurs during the process, it returns nil and the error.
func GetVersionStringsBelow(depName string, depVersion string, limit int, knowledge *bun.DB) ([]string, error) {

	toReturn := []string{}

	versions, err := GetVersionStrings(depName, knowledge)
	if err != nil {
		return nil, err
	}

	constraint, err := nodesemver.ParseConstraint("< " + depVersion)
	if err != nil {
		return nil, err
	}

	for _, version := range versions {
		parsedVersion, err := nodesemver.ParseSemver(version)
		if err != nil {
			return nil, err
		}
		if nodesemver.Satisfies(parsedVersion, constraint, true) {
			toReturn = append(toReturn, version)
		}
	}

	// sortSemvers(toReturn)
	if len(toReturn) == 0 {
		return []string{}, nil
	}
	return toReturn[0:min(limit, len(versions))], nil

}

// GetVersionStringsAbove returns a slice of version strings that are above a specified dependency version.
// It takes the dependency name, dependency version, and a limit as input parameters.
// The function retrieves all version strings for the given dependency name using GetVersionStrings function.
// It then checks if each version satisfies the constraint "> depVersion" using nodesemver package.
// The function returns a slice of version strings that satisfy the constraint, limited by the specified limit.
// If no versions satisfy the constraint, an empty slice is returned.
// An error is returned if there is any issue retrieving the version strings or parsing the versions.
func GetVersionStringsAbove(depName string, depVersion string, limit int, knowledge *bun.DB) ([]string, error) {

	toReturn := []string{}

	versions, err := GetVersionStrings(depName, knowledge)
	if err != nil {
		return nil, err
	}

	constraint, err := nodesemver.ParseConstraint("> " + depVersion)
	if err != nil {
		return nil, err
	}

	for _, version := range versions {
		parsedVersion, err := nodesemver.ParseSemver(version)
		if err != nil {
			return nil, err
		}
		if nodesemver.Satisfies(parsedVersion, constraint, true) {
			toReturn = append(toReturn, version)
		}
	}

	// sortSemvers(toReturn)

	if len(toReturn) == 0 {
		return []string{}, nil
	}
	return toReturn[0:min(limit, len(versions))], nil

}

// GetFirstVersionString returns the first version string of a given dependency name.
// It retrieves the version strings using the GetVersionStrings function and returns the first version in the sorted list.
// If there are no version strings available, it returns an error with the message "No versions".
func GetFirstVersionString(depName string, knowledge *bun.DB) (string, error) {
	versions, err := GetVersionStrings(depName, knowledge)
	if err != nil {
		return "", err
	}

	if len(versions) == 0 {
		return "", fmt.Errorf("no versions")
	} else {
		return versions[0], nil
	}
}

// GetLastVersionString returns the last version string of a given dependency name.
// It retrieves the version strings using the GetVersionStrings function and returns the last version in the sorted list.
// If there are no versions available, it returns an error with the message "No versions".
func GetLastVersionString(depName string, knowledge *bun.DB) (string, error) {
	versions, err := GetVersionStrings(depName, knowledge)
	if err != nil {
		return "", err
	}

	if len(versions) == 0 {
		return "", fmt.Errorf("no versions")
	} else {
		return versions[len(versions)-1], nil
	}
}

type semverCompVers []string

// Len returns the length of the semverCompVers slice.
// It implements the Len method of the sort.Interface interface.
func (s semverCompVers) Len() int {
	return len(s)
}

func (s semverCompVers) Swap(i, j int) {
	// Swap swaps the elements at index i and j.
	s[i], s[j] = s[j], s[i]
}

// Less compares two semverCompVers values at index i and j and returns true if the value at index i is less than the value at index j.
// It uses nodesemver.ParseSemver to parse the semver strings and compares the parsed versions using v1.LT(v2, false).
// If there is an error encountered during semver parsing, it logs the error and returns false.
func (s semverCompVers) Less(i int, j int) bool {
	v1, err := nodesemver.ParseSemver(s[i])
	if err != nil {
		log.Printf("Error encountered during semver parsing: %s.", err)
	}
	v2, err := nodesemver.ParseSemver(s[j])
	if err != nil {
		log.Printf("Error encountered during semver parsing: %s.", err)
	}
	return v1.LT(v2, false)
}

// sortSemvers sorts the given slice of semver versions in ascending order.
// It uses the semverCompVers custom sort implementation to compare the versions.
// The sorted slice is returned.
func sortSemvers(versions []string) []string {
	sort.Sort(semverCompVers(versions))
	return versions
}

// min returns the minimum of two integers.
// It takes two integers, a and b, as input and returns the smaller of the two.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
