// ©AngelaMos | 2026
// types.go

package token

type TypeDescriptor struct {
	Type           Type   `json:"type"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	ArtifactKind   string `json:"artifact_kind"`
	Enabled        bool   `json:"enabled"`
	DisabledReason string `json:"disabled_reason,omitempty"`
}

const mysqlDisabledReason = "Requires direct TCP exposure (port 3306). Not reachable via Cloudflare Tunnel — only enable on a VPS with raw TCP access."

func TypeDescriptors(mysqlEnabled bool) []TypeDescriptor {
	descriptors := []TypeDescriptor{
		{
			Type:         TypeWebbug,
			Name:         "Web Bug Pixel",
			Description:  "1x1 transparent GIF that fires when fetched. Embed in HTML emails or web pages.",
			ArtifactKind: string(KindURL),
			Enabled:      true,
		},
		{
			Type:         TypeSlowRedirect,
			Name:         "Slow Redirect",
			Description:  "Browser-fingerprinting page that redirects to a destination URL after collecting client metadata.",
			ArtifactKind: string(KindURL),
			Enabled:      true,
		},
		{
			Type:         TypeDocx,
			Name:         "Microsoft Word Document",
			Description:  "DOCX with an embedded INCLUDEPICTURE field that calls home when the document opens.",
			ArtifactKind: string(KindFile),
			Enabled:      true,
		},
		{
			Type:         TypePDF,
			Name:         "PDF Document",
			Description:  "PDF with an /AA open-action URI that fires in Adobe Acrobat Reader.",
			ArtifactKind: string(KindFile),
			Enabled:      true,
		},
		{
			Type:         TypeKubeconfig,
			Name:         "Kubernetes Config",
			Description:  "kubeconfig pointing kubectl at a fake K8s API server that records every request.",
			ArtifactKind: string(KindText),
			Enabled:      true,
		},
		{
			Type:         TypeEnvfile,
			Name:         ".env File",
			Description:  "Plausible production .env with shuffled bait credentials and an embedded canary URL.",
			ArtifactKind: string(KindText),
			Enabled:      true,
		},
		{
			Type:         TypeMySQL,
			Name:         "MySQL Connection String",
			Description:  "Fake MySQL endpoint that records any authentication attempt.",
			ArtifactKind: string(KindConnectionString),
			Enabled:      mysqlEnabled,
		},
	}
	if !mysqlEnabled {
		descriptors[len(descriptors)-1].DisabledReason = mysqlDisabledReason
	}
	return descriptors
}
