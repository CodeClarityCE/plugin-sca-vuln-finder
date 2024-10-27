# Service - SCA vulnerability finder 

<br>

<div align="center">
    <img src="https://user-images.githubusercontent.com/124595411/233356880-fdc7ea8a-8b1d-4991-8726-67b47e91df9e.svg" width="400px" />
</div>

<br>

## Purpose

The vulnerability finder service finds known vulnerabilities for the dependencies in a source code project; that is it validates whether the installed versions are known to be vulnerable. This information is given by vulnerability sources such as the NVD and the OSV. 

<br> It is the second stage of the Software Composition Analysis process.

1. Identify dependencies (SBOM)
2. Identify known vulnerabile dependencies (This service)
3. Identify licenses & license compliance
4. Compute and verify upgrades to the application

<br>

## Current Features

1. Identifies vulnerable package-managed dependencies
2. Language agnostic. 
   <br> This service has been designed in a language agnositc fashion. Adding support for a new language takes at most 10min.

<br>

## Future Features

1. Identify vulnerable self-managed dependencies (script tags, library files, etc...)

<br>

## Dev Usage

To execute this service for development purposes, two paramters need to be supplied to the IDE or terminal:

```
Usage of service-sca-vuln-finder:
  -output-file string
    	Absolute Path to the output file (Required)
  -sbom-input-file string
    	Absolute Path to the sbom service's output file (Required)
```
<br>

## How to add support for a new language?

Although the service is written in a language-agnostic fashion, adding a new language requires adding a little bit of code.

In run.go:Start(), you must create a new vulnerability matcher instance for your language (example for js):

```go
// Check which language was requested
if languageId == "JS" {
  vulnMatcher.VulnerabilityMatcher{
    Ecosystems: []ecoSystemTypes.Ecosystem{
      ecoSystemTypes.NODEJS_OR_JS,
    },
    ConflictResolver:  conflictResolver.TrustOSVConflictHeuristic,
    PackageRepository: &npmRepository.NpmPackageRepository,
  }
}
```

1. In `Ecosystems` you define what the ecosystem is that you want to match, PHP, GO, Python, ...
2. In `ConflictResolver` you define what conflict resolver to use. Use the same as the other languages.
3. Most importantly, in `PackageRepository` you define - a to-be implemented the package repository abstraction - for the language/ecosystem to be analyzed.

This `PackageRepository` must provide 5 simple functions:
  1. `GetVersionStrings func(depName string) ([]string, error)` get all version strings (only version numbers, not info about each version) of the dependency
  2. `GetVersionStringsBelow func(depName string, depVersion string, limit int) ([]string, error)` get all version strings below a given semver of the dependency
  3. `GetVersionStringsAbove func(depName string, depVersion string, limit int) ([]string, error)` get all version strings above a given semver of the dependency
  4. `GetFirstVersionString func(depName string) (string, error)` get first version of the dependency
  5. `GetLastVersionString func(depName string) (string, error)` get last version of the dependency
