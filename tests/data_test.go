package main

import (
	"encoding/json"
	"io/fs"
	"os"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
)

func getSBOM(folder string) (sbomTypes.Output, error) {
	// Read the JSON file inside the fixture folder
	jsonData, err := fs.ReadFile(os.DirFS(folder), "sbom.json")
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
