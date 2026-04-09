// ©AngelaMos | 2026
// registry.go

package parser

type Registry struct {
	parsers []DependencyParser
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(p DependencyParser) {
	r.parsers = append(r.parsers, p)
}

func (r *Registry) Detect(dir string) []DependencyParser {
	var matched []DependencyParser
	for _, p := range r.parsers {
		if p.Detect(dir) {
			matched = append(matched, p)
		}
	}
	return matched
}

func (r *Registry) All() []DependencyParser {
	return r.parsers
}

func RegisterAll(reg *Registry) {
	reg.Register(NewGoModParser())
	reg.Register(NewNodeParser())
	reg.Register(NewPythonParser())
}
