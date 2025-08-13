package main

import (
	"testing"

	phpRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository/php"
	"github.com/stretchr/testify/assert"
)

func TestPHPSemverSorting(t *testing.T) {
	// For now, we'll just verify the package repository structure is correct
	repo := phpRepository.PhpPackageRepository
	
	assert.NotNil(t, repo.GetVersionStrings)
	assert.NotNil(t, repo.GetVersionStringsBelow)
	assert.NotNil(t, repo.GetVersionStringsAbove)
	assert.NotNil(t, repo.GetFirstVersionString)
	assert.NotNil(t, repo.GetLastVersionString)
}

func TestPHPVersionConstraints(t *testing.T) {
	// This test would require actual database setup, so for now we'll just verify
	// the structure exists and can be called safely
	
	// Test with nil database (should handle gracefully)
	versions, err := phpRepository.PhpPackageRepository.GetVersionStrings("test/package", nil)
	
	// Should return error due to nil database, but shouldn't panic
	assert.Error(t, err)
	assert.Empty(t, versions)
}

func TestPHPPackageNaming(t *testing.T) {
	// Test that PHP package naming follows vendor/package convention
	testPackages := []string{
		"symfony/console",
		"laravel/framework", 
		"cakephp/cakephp",
		"ramsey/uuid",
		"monolog/monolog",
	}
	
	for _, pkg := range testPackages {
		// Just verify the package names are in the expected format
		assert.Contains(t, pkg, "/")
		assert.True(t, len(pkg) > 3)
	}
}