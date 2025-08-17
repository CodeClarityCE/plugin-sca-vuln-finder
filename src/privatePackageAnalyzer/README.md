# Private Package Vulnerability Analyzer

This module provides comprehensive vulnerability analysis for private packages in both JavaScript and PHP projects. It integrates with the main vulnerability finder to detect security issues specific to private repositories and packages.

## Overview

The Private Package Vulnerability Analyzer extends standard vulnerability detection to address security concerns unique to private packages:

- **License compliance issues** in proprietary packages
- **Security policy violations** for private repositories
- **Authentication failures** in private package resolution
- **Pattern-based vulnerability detection** for common security anti-patterns
- **Supply chain risk assessment** for private dependencies

## Architecture

### Core Components

1. **PrivatePackageAnalyzer** - Main analyzer class
2. **Private Repository Detection** - Identifies packages from private repositories
3. **Pattern-Based Analysis** - Detects known problematic patterns
4. **License Compliance Checker** - Validates license requirements
5. **Security Policy Validator** - Enforces organizational security policies

### Integration Points

- **vuln-finder/src/run.go** - Main integration point
- **SBOM Processing** - Extracts private repository metadata
- **Vulnerability Database** - Cross-references with known vulnerabilities
- **Reporting** - Generates private package-specific vulnerability reports

## Vulnerability Detection Categories

### 1. Pattern-Based Vulnerabilities

Detects packages with problematic naming patterns:

- **Debug packages in production** (`debug`, `test` patterns)
- **Internal authentication packages** (`internal-auth` pattern)
- **Legacy packages** (`legacy` pattern)
- **Development tools in production** (`dev`, `test` patterns)

**Example Detection:**
```
PRIVATE-PATTERN-DEBUG-company/debug-helper
- Severity: MEDIUM
- CWE: CWE-200 (Information Exposure)
- Description: Debug package in production environment
```

### 2. License Compliance Issues

Validates license information for private packages:

- **Missing licenses** - No license information available
- **Restrictive licenses** - GPL, AGPL, SSPL that may cause legal issues
- **Proprietary license validation** - Ensures proper licensing

**Example Detection:**
```
PRIVATE-LICENSE-MISSING-acme/internal-library
- Severity: MEDIUM  
- CWE: CWE-1104 (Use of Unmaintained Third Party Components)
- Description: Private package missing license information
```

### 3. Security Policy Violations

Enforces organizational security policies:

- **Authentication failures** - Packages that failed authentication
- **Untrusted repositories** - Packages from non-approved sources
- **Test packages in production** - Development packages in production builds
- **Naming convention violations** - Packages that don't follow standards

**Example Detection:**
```
PRIVATE-AUTH-FAILURE-company/restricted-package
- Severity: HIGH
- CWE: CWE-287 (Improper Authentication)  
- Description: Authentication failed for private package repository
```

### 4. Supply Chain Risk Assessment

Analyzes dependency complexity and risk:

- **High dependency count** - Packages with excessive dependencies (>50)
- **Transitive dependency analysis** - Risk from indirect dependencies
- **Repository trust validation** - Verifies repository authenticity

**Example Detection:**
```
PRIVATE-SUPPLY-CHAIN-RISK-enterprise/mega-framework
- Severity: LOW
- CWE: CWE-1104 (Use of Unmaintained Third Party Components)
- Description: Package has high dependency count (75 dependencies)
```

## Configuration

### Private Repository Detection

The analyzer automatically detects private packages using multiple strategies:

1. **SBOM Metadata** - Uses private repository information from enhanced SBOMs
2. **Repository URL Analysis** - Identifies private repository patterns
3. **Package Naming Heuristics** - Detects private package naming conventions
4. **License Analysis** - Identifies proprietary and internal licenses

### Detection Patterns

**Private Repository URLs:**
- `repo.company.com`
- `packages.company.com`
- `gitlab.company.com`
- `github.company.com`
- `*.internal`
- `repo.packagist.com`

**Private Package Patterns:**
- `company/*`
- `acme/*`
- `internal/*`
- `private/*`
- `enterprise/*`
- `corp/*`

**License Indicators:**
- `Proprietary`
- `Confidential`
- `Internal`

## Usage Examples

### Basic Integration

```go
// In vuln-finder main analysis loop
privateAnalyzer := privatePackageAnalyzer.NewPrivatePackageAnalyzer(knowledge)
privateVulns := privateAnalyzer.AnalyzePrivatePackages(sbom, workspace.Dependencies)
vulns = append(vulns, privateVulns...)
```

### Custom Pattern Detection

The analyzer can be extended with custom patterns:

```go
problematicPatterns := []struct {
    pattern     string
    description string
    severity    string
    cwe         string
}{
    {
        pattern:     "experimental",
        description: "Experimental package in production",
        severity:    "HIGH",
        cwe:         "CWE-1104",
    },
}
```

### Environment-Based Configuration

Private package analysis respects environment configuration:

- **Development** - More lenient analysis, allows debug packages
- **Staging** - Moderate analysis, warns about test packages
- **Production** - Strict analysis, flags all policy violations

## Vulnerability Severity Mapping

| Pattern Type | Severity | Typical CWE | Description |
|-------------|----------|-------------|-------------|
| Debug in Production | MEDIUM | CWE-200 | Information disclosure risk |
| Auth Failures | HIGH | CWE-287 | Authentication bypass risk |
| Missing License | MEDIUM | CWE-1104 | Legal/compliance risk |
| Test in Production | MEDIUM | CWE-489 | Debug code exposure |
| Supply Chain Risk | LOW | CWE-1104 | Dependency complexity |
| Restrictive License | LOW | Legal | Legal compatibility issues |

## Integration with PHP SBOM

When analyzing PHP projects with private repository support enabled:

1. **Enhanced SBOM Processing** - Extracts private repository metadata
2. **Repository Authentication** - Uses auth.json and environment variables
3. **Package Resolution** - Resolves private package metadata
4. **Vulnerability Cross-Reference** - Checks against known vulnerability databases

### PHP-Specific Features

- **Composer.json Repository Analysis** - Processes private repository configurations
- **Auth.json Integration** - Uses Composer authentication files
- **Framework-Aware Analysis** - Considers PHP framework security patterns
- **Extension Compatibility** - Validates against PHP extension requirements

## Testing

### Unit Tests

```bash
go test ./tests/private_package_test.go -v
```

### Integration Tests

```bash
# Test with PHP SBOM containing private packages
ENABLE_PRIVATE_REPOS=true go test ./tests/e2e_php_test.go -v
```

### Manual Testing

```bash
# Create test project with private packages
mkdir test-private && cd test-private
# Add composer.json with private repositories
# Run PHP SBOM generation with private repo support
# Run vulnerability analysis
```

## Performance Considerations

### Optimization Strategies

1. **Caching** - Package metadata cached with TTL
2. **Pattern Matching** - Efficient string matching algorithms
3. **Lazy Loading** - Private analysis only when needed
4. **Batch Processing** - Analyze multiple packages together

### Impact Assessment

- **Standard Projects** - No performance impact (analyzer skipped)
- **Private Package Projects** - ~10-15% analysis time increase
- **Memory Usage** - Minimal increase due to pattern matching
- **Network Requests** - No additional requests (uses SBOM data)

## Security Considerations

### Data Handling

- **No Credential Logging** - Never logs authentication information
- **Secure Pattern Storage** - Patterns stored securely in memory
- **Minimal Network Exposure** - Uses existing SBOM data primarily
- **Error Handling** - Graceful degradation on analysis failures

### Privacy Protection

- **Package Name Anonymization** - Option to anonymize package names in reports
- **Repository URL Filtering** - Filters sensitive repository information
- **Audit Trail** - Maintains audit logs for security reviews

## Future Enhancements

### Planned Features

1. **Custom Rule Engine** - User-defined vulnerability patterns
2. **Machine Learning Detection** - AI-powered pattern recognition
3. **Dependency Graph Analysis** - Advanced supply chain risk assessment
4. **Real-time Monitoring** - Continuous vulnerability monitoring
5. **Integration with Security Scanners** - SAST/DAST tool integration

### API Extensions

- **REST API** - HTTP API for external tool integration
- **Webhook Support** - Real-time notifications for new vulnerabilities
- **Plugin Architecture** - Custom analyzer plugins
- **Reporting Formats** - SARIF, SPDX, CycloneDX output formats

## Troubleshooting

### Common Issues

1. **No private packages detected**
   - Verify SBOM contains private repository information
   - Check package naming patterns match detection rules
   - Ensure private repository URLs are configured

2. **False positives**
   - Review detection patterns for accuracy
   - Adjust severity thresholds in configuration
   - Add package exclusions for known-good packages

3. **Performance issues**
   - Enable package metadata caching
   - Reduce analysis scope with filters
   - Use incremental analysis for large projects

### Debug Logging

```bash
export VULN_FINDER_DEBUG=true
export PRIVATE_ANALYSIS_DEBUG=true
```

## Contributing

### Adding New Patterns

1. Define pattern in `analyzePrivatePackagePatterns()`
2. Add severity and CWE mapping
3. Create unit tests for the pattern
4. Update documentation

### Custom Vulnerability Sources

1. Implement custom detection logic
2. Add new vulnerability source type
3. Integrate with main analysis pipeline
4. Add comprehensive testing

## Related Documentation

- [Private Repository Implementation](../../../php-sbom/src/private_repos/README.md)
- [Vulnerability Finder Architecture](../README.md)
- [PHP SBOM Generation](../../../php-sbom/README.md)
- [Security Best Practices](../../SECURITY.md)