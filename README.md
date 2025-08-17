<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
  <img alt="codeclarity-logo" src="https://github.com/CodeClarityCE/identity/blob/main/logo/vectorized/logo_name_black.svg">
</picture>
<br>
<br>

Secure your software empower your team.

[![License](https://img.shields.io/github/license/codeclarityce/codeclarity-dev)](LICENSE.txt)

<details open="open">
<summary>Table of Contents</summary>

- [CodeClarity Plugin - Vulnerability Finder](#codeclarity-plugin---vulnerability-finder)
  - [Contributing](#contributing)
  - [Reporting Issues](#reporting-issues)
  - [Purpose](#purpose)
  - [Current Features](#current-features)
  - [Future Features](#future-features)
  - [Dev Usage](#dev-usage)
  - [How to add support for a new language?](#how-to-add-support-for-a-new-language)
- [Acknowledgement of Copyright and Co-Authorship](#acknowledgement-of-copyright-and-co-authorship)


</details>

---

# CodeClarity Plugin - Vulnerability Finder

## Contributing

If you'd like to contribute code or documentation, please see [CONTRIBUTING.md](https://github.com/CodeClarityCE/codeclarity-dev/blob/main/CONTRIBUTING.md) for guidelines on how to do so.

## Reporting Issues

Please report any issues with the setup process or other problems encountered while using this repository by opening a new issue in this project's GitHub page.

## Purpose

The vulnerability finder service finds known vulnerabilities for the dependencies in a source code project; that is it validates whether the installed versions are known to be vulnerable. This information is given by vulnerability sources such as the NVD and the OSV. 

<br> It is the second stage of the Software Composition Analysis process.

1. Identify dependencies (SBOM)
2. Identify known vulnerabile dependencies (This service)
3. Identify licenses & license compliance
4. Compute and verify upgrades to the application

<br>

## Current Features

1. **Multi-language Support**: JavaScript (npm, yarn, pnpm) and PHP (Composer)
2. **Vulnerability Sources**: OSV Database, NVD, FriendsOfPHP Security Advisories
3. **PHP Extension Analysis**: Vulnerability detection for PHP extensions
4. **Language-agnostic Architecture**: Easily extensible for new languages

### Supported Languages

| Language | Package Managers | Vulnerability Sources | Extension Support |
|----------|------------------|----------------------|-------------------|
| JavaScript | npm, yarn, pnpm | OSV, NVD | ❌ |
| PHP | Composer | OSV (Packagist), FriendsOfPHP, NVD | ✅ |

### PHP-Specific Features

- **Composer Package Analysis**: Full support for `composer.lock` dependency analysis
- **PHP Extension Vulnerabilities**: Detection of vulnerabilities in PHP extensions (openssl, curl, gd, etc.)
- **Multi-source Vulnerability Data**: 
  - OSV Packagist ecosystem
  - FriendsOfPHP Security Advisories 
  - NVD database for PHP components
- **Framework Awareness**: Enhanced analysis for Laravel, Symfony, WordPress, etc.

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

# Acknowledgement of Copyright and Co-Authorship

This software was developed as part of the research project “FNR JUMP SecuBox”, funded by the Luxembourg National Research Fund (FNR), grant number JUMP21/16693582/SecuBox (hereafter the “Project”).
The software was developed at the University of Luxembourg (hereafter the “University”) and is subject to its intellectual property policy. Accordingly, the copyright of this software is held by the University of Luxembourg.
The development of this software involved contributions from several researchers affiliated with the University during the Project period. Their work was instrumental in achieving the technical and scientific objectives of the Project.