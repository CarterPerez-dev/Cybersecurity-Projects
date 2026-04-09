// ©AngelaMos | 2026
// cyclonedx.go

package sbom

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/CarterPerez-dev/bomber/internal/config"
	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/google/uuid"
)

type CycloneDXGenerator struct{}

func NewCycloneDXGenerator() *CycloneDXGenerator {
	return &CycloneDXGenerator{}
}

func (g *CycloneDXGenerator) Generate(graphs []*types.DependencyGraph) ([]byte, error) {
	doc := cdxDocument{
		BOMFormat:   config.CycloneDXFormat,
		SpecVersion: config.CycloneDXVersion,
		Version:     1,
		SerialNum:   fmt.Sprintf("urn:uuid:%s", uuid.New().String()),
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []cdxTool{
				{
					Vendor:  config.ToolVendor,
					Name:    config.ToolName,
					Version: config.ToolVersion,
				},
			},
		},
		Components:   []cdxComponent{},
		Dependencies: []cdxDependency{},
	}

	for _, graph := range graphs {
		for _, pkg := range graph.Nodes {
			if pkg.PURL == graph.Root.PURL {
				continue
			}

			comp := cdxComponent{
				Type:    "library",
				Name:    pkg.Name,
				Version: pkg.Version,
				PURL:    pkg.PURL,
				BOMRef:  pkg.PURL,
			}

			for _, cs := range pkg.Checksums {
				comp.Hashes = append(comp.Hashes, cdxHash{
					Alg:     mapCDXAlgo(cs.Algorithm),
					Content: cs.Value,
				})
			}

			doc.Components = append(doc.Components, comp)
		}

		for parentPURL, children := range graph.Edges {
			dep := cdxDependency{
				Ref:       parentPURL,
				DependsOn: make([]string, len(children)),
			}
			copy(dep.DependsOn, children)
			doc.Dependencies = append(doc.Dependencies, dep)
		}
	}

	return json.MarshalIndent(doc, "", "  ")
}

type cdxDocument struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Version      int             `json:"version"`
	SerialNum    string          `json:"serialNumber"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies"`
}

type cdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []cdxTool `json:"tools"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type    string    `json:"type"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	PURL    string    `json:"purl"`
	BOMRef  string    `json:"bom-ref"`
	Hashes  []cdxHash `json:"hashes,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

func mapCDXAlgo(algo string) string {
	switch algo {
	case "SHA-256", "SHA256":
		return "SHA-256"
	case "SHA-512", "SHA512":
		return "SHA-512"
	case "SHA-1", "SHA1":
		return "SHA-1"
	default:
		return algo
	}
}
