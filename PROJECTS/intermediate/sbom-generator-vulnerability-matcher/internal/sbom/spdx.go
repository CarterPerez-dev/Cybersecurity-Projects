// ©AngelaMos | 2026
// spdx.go

package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/CarterPerez-dev/bomber/internal/config"
	"github.com/CarterPerez-dev/bomber/pkg/types"
)

type SPDXGenerator struct{}

func NewSPDXGenerator() *SPDXGenerator {
	return &SPDXGenerator{}
}

func (g *SPDXGenerator) Generate(graphs []*types.DependencyGraph) ([]byte, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	docName := "bomber-sbom"
	if len(graphs) > 0 {
		docName = graphs[0].Root.Name
	}

	nsHash := fmt.Sprintf("%x", sha256.Sum256([]byte(docName+now)))
	namespace := fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s", docName, nsHash[:16])

	doc := spdxDocument{
		SPDXVersion:       config.SPDXVersion,
		DataLicense:       config.SPDXDataLicense,
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              docName,
		DocumentNamespace: namespace,
		CreationInfo: spdxCreationInfo{
			Created: now,
			Creators: []string{
				fmt.Sprintf("Tool: %s-%s", config.ToolName, config.ToolVersion),
			},
		},
		Packages:      []spdxPackage{},
		Relationships: []spdxRelationship{},
	}

	for _, graph := range graphs {
		rootRef := sanitizeSPDXID(graph.Root.PURL)

		doc.Relationships = append(doc.Relationships, spdxRelationship{
			Element: "SPDXRef-DOCUMENT",
			Type:    "DESCRIBES",
			Related: rootRef,
		})

		for _, pkg := range graph.Nodes {
			spdxPkg := spdxPackage{
				SPDXID:           sanitizeSPDXID(pkg.PURL),
				Name:             pkg.Name,
				VersionInfo:      pkg.Version,
				DownloadLocation: "NOASSERTION",
				FilesAnalyzed:    false,
				Supplier:         "NOASSERTION",
				ExternalRefs: []spdxExternalRef{
					{
						Category: "PACKAGE-MANAGER",
						Type:     "purl",
						Locator:  pkg.PURL,
					},
				},
			}

			for _, cs := range pkg.Checksums {
				spdxPkg.Checksums = append(spdxPkg.Checksums, spdxChecksum{
					Algorithm: mapChecksumAlgo(cs.Algorithm),
					Value:     cs.Value,
				})
			}

			doc.Packages = append(doc.Packages, spdxPkg)
		}

		for parentPURL, children := range graph.Edges {
			parentRef := sanitizeSPDXID(parentPURL)
			for _, childPURL := range children {
				childRef := sanitizeSPDXID(childPURL)
				doc.Relationships = append(doc.Relationships, spdxRelationship{
					Element: parentRef,
					Type:    "DEPENDS_ON",
					Related: childRef,
				})
			}
		}
	}

	return json.MarshalIndent(doc, "", "  ")
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	Supplier         string            `json:"supplier"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
}

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type spdxExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	Element string `json:"spdxElementId"`
	Type    string `json:"relationshipType"`
	Related string `json:"relatedSpdxElement"`
}

func sanitizeSPDXID(purl string) string {
	r := strings.NewReplacer(
		"/", "-",
		"@", "-",
		":", "-",
		".", "-",
		"%", "-",
	)
	return "SPDXRef-" + r.Replace(purl)
}

func mapChecksumAlgo(algo string) string {
	switch strings.ToUpper(algo) {
	case "SHA-256", "SHA256":
		return "SHA256"
	case "SHA-512", "SHA512":
		return "SHA512"
	case "SHA-1", "SHA1":
		return "SHA1"
	default:
		return algo
	}
}
