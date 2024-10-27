package conflictResolver

import (
	packageRepository "github.com/CodeClarityCE/plugin-sca-vuln-finder/src/repository"
	"github.com/CodeClarityCE/plugin-sca-vuln-finder/src/types/conflict"
)

func TrustOSV(packageRepository packageRepository.PackageRepository) conflict.ResolveWinner {
	return conflict.OSV
}
