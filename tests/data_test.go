package main

import (
	"encoding/json"
	"os"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
)

func getSBOM(folder string) (sbomTypes.Output, error) {
	filePath := folder + "/sbom.json"

	// Read the JSON file
	jsonData, err := os.ReadFile(filePath)
	if err != nil {
		return sbomTypes.Output{}, err
	}

	var sbom sbomTypes.Output
	err = json.Unmarshal(jsonData, &sbom)
	if err != nil {
		return sbomTypes.Output{}, err
	}

	return sbom, nil
}
