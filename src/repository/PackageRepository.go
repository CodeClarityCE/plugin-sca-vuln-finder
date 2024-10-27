package repository

import "github.com/uptrace/bun"

type PackageRepository struct {
	GetVersionStrings      func(depName string, knowledge *bun.DB) ([]string, error)
	GetVersionStringsBelow func(depName string, depVersion string, limit int, knowledge *bun.DB) ([]string, error)
	GetVersionStringsAbove func(depName string, depVersion string, limit int, knowledge *bun.DB) ([]string, error)
	GetFirstVersionString  func(depName string, knowledge *bun.DB) (string, error)
	GetLastVersionString   func(depName string, knowledge *bun.DB) (string, error)
}
