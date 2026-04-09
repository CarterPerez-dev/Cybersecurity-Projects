// ©AngelaMos | 2026
// parser.go

package parser

import "github.com/CarterPerez-dev/bomber/pkg/types"

type DependencyParser interface {
	Detect(dir string) bool
	Parse(dir string) (*types.DependencyGraph, error)
	Ecosystem() types.Ecosystem
}
