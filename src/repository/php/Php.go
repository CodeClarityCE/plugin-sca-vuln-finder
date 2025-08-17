package php

import (
	"context"
	"fmt"
	"log"
	"sort"

	packageRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository"
	nodesemver "github.com/CodeClarityCE/utility-node-semver"
	knowledge_db "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

var PhpPackageRepository = packageRepository.PackageRepository{
	GetVersionStrings:      GetVersionStrings,
	GetVersionStringsBelow: GetVersionStringsBelow,
	GetVersionStringsAbove: GetVersionStringsAbove,
	GetFirstVersionString:  GetFirstVersionString,
	GetLastVersionString:   GetLastVersionString,
}

// GetVersionStrings retrieves the version strings of a given dependency.
// It first checks if the version strings are already cached in the dependencyVersionsCache.
// If not, it queries the database to fetch the version strings and stores them in the cache for future use.
// The dependency name can be in the format "vendor/package".
// It returns the version strings in ascending order and an error if any.
func GetVersionStrings(depName string, knowledge *bun.DB) ([]string, error) {
	versions := []string{}
	if knowledge == nil {
		return versions, fmt.Errorf("database connection is nil")
	}
	dependency := knowledge_db.Package{}
	ctx := context.Background()
	exists, err := knowledge.NewSelect().Model(&dependency).Relation("Versions").Where("name = ?", depName).Exists(ctx)
	if err != nil {
		return nil, err
	}
	if !exists {
		// TODO: Implement PHP package updates
		// For now, return empty versions if package not found
		log.Printf("PHP package %s not found in knowledge database", depName)
		return versions, nil
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

// GetVersionStringsBelow retrieves the version strings of a given dependency that are below a specified version.
// It returns the version strings in ascending order and an error if any.
func GetVersionStringsBelow(depName string, depVersion string, limit int, knowledge *bun.DB) ([]string, error) {
	toReturn := []string{}
	if knowledge == nil {
		return toReturn, fmt.Errorf("database connection is nil")
	}

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

	// Apply limit if specified
	if limit > 0 && len(toReturn) > limit {
		toReturn = toReturn[:limit]
	}

	return toReturn, nil
}

// GetVersionStringsAbove retrieves the version strings of a given dependency that are above a specified version.
// It returns the version strings in ascending order and an error if any.
func GetVersionStringsAbove(depName string, depVersion string, limit int, knowledge *bun.DB) ([]string, error) {
	toReturn := []string{}
	if knowledge == nil {
		return toReturn, fmt.Errorf("database connection is nil")
	}

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

	// Apply limit if specified
	if limit > 0 && len(toReturn) > limit {
		toReturn = toReturn[:limit]
	}

	return toReturn, nil
}

// GetFirstVersionString retrieves the first (lowest) version string of a given dependency.
// It returns the version string and an error if any.
func GetFirstVersionString(depName string, knowledge *bun.DB) (string, error) {
	if knowledge == nil {
		return "", fmt.Errorf("database connection is nil")
	}
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

// GetLastVersionString retrieves the last (highest) version string of a given dependency.
// It returns the version string and an error if any.
func GetLastVersionString(depName string, knowledge *bun.DB) (string, error) {
	if knowledge == nil {
		return "", fmt.Errorf("database connection is nil")
	}
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
		return false
	}
	v2, err := nodesemver.ParseSemver(s[j])
	if err != nil {
		log.Printf("Error encountered during semver parsing: %s.", err)
		return false
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
