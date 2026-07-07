// ©AngelaMos | 2026
// detail.go

package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/CarterPerez-dev/nadezhda/internal/rank"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const (
	cvssMaxScore = 10.0
	nvdBaseURL   = "https://nvd.nist.gov/vuln/detail/"
	detailIndent = 3
	metaDivider  = "  ·  "
)

func (m Model) renderDetailBody() string {
	s := m.selected()
	c := s.Cluster
	w := m.bodyWidth()
	t := m.theme
	indent := strings.Repeat(" ", detailIndent)
	var b strings.Builder

	b.WriteString(t.HeadlineSel.Width(w).Render(headlineOf(c)))
	b.WriteString("\n")
	b.WriteString(m.detailMeta(s))
	b.WriteString("\n\n")

	b.WriteString(m.sectionHeader("OUTLETS", w))
	b.WriteString("\n")
	for _, a := range sortedArticles(c) {
		b.WriteString(m.renderArticle(a, w, indent))
	}

	cves := m.sortedDetailCVEs(c)
	if len(cves) > 0 {
		b.WriteString(m.sectionHeader("VULNERABILITIES", w))
		b.WriteString("\n")
		for _, v := range cves {
			b.WriteString(m.renderCVE(v, w, indent))
		}
	}

	if note, ok := m.notes[c.ClusterID]; ok {
		b.WriteString(m.sectionHeader("AI IDEAS", w))
		b.WriteString("\n")
		b.WriteString(t.fg(colorMagenta).Bold(true).Render(strings.ToUpper(note.Format)) + "\n\n")
		b.WriteString(m.wrapIndent(note.Summary, w, t.Text) + "\n\n")
		b.WriteString(m.wrapIndent(note.Why, w, t.Muted) + "\n\n")
		for i, a := range note.Angles {
			b.WriteString(m.wrapIndent(fmt.Sprintf("%d. %s", i+1, a), w, t.Text) + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func (m Model) detailMeta(s rank.Scored) string {
	t := m.theme
	c := s.Cluster
	parts := []string{
		t.spectrumBar(s.Score, colScoreBarW) + " " + t.Meta.Bold(true).Render(fmt.Sprintf("%.2f", s.Score)),
		t.Muted.Render(fmt.Sprintf("%d outlets", outletCount(c))),
	}
	if mx := clusterMaxCVSS(c); mx != nil {
		b := cvssBand(mx)
		parts = append(parts, t.Muted.Render("CVSS ")+t.bandFG(b).Bold(true).Render(cvssString(mx)))
	}
	if me := clusterMaxEPSS(c); me != nil {
		b := epssBand(me)
		parts = append(parts, t.Muted.Render("EPSS ")+t.bandFG(b).Bold(true).Render(epssString(me)))
	}
	parts = append(parts,
		t.Muted.Render("first "+relativeAge(c.FirstSeen, m.now)),
		t.Muted.Render("last "+relativeAge(c.LastSeen, m.now)),
	)
	return strings.Join(parts, t.Dim.Render(metaDivider))
}

func (m Model) sectionHeader(title string, w int) string {
	t := m.theme
	head := t.fg(colorViolet).Bold(true).Render(glyphSelected + " " + title + " ")
	n := w - lipgloss.Width(head)
	if n < 0 {
		n = 0
	}
	return head + t.Dim.Render(strings.Repeat(ruleBody, n))
}

func (m Model) renderArticle(a store.DigestArticle, w int, indent string) string {
	t := m.theme
	head := t.fg(colorCyan).Bold(true).Render(a.SourceName) +
		t.Dim.Render(metaDivider) + t.Muted.Render(relativeAge(a.PublishedAt, m.now))
	title := m.wrapIndent(a.Title, w, t.Text)
	url := indent + t.Link.Render(truncate(a.CanonicalURL, w-detailIndent))
	return head + "\n" + title + "\n" + url + "\n\n"
}

func (m Model) renderCVE(v store.CVE, w int, indent string) string {
	t := m.theme
	bnd := cvssBand(v.CVSSScore)
	var b strings.Builder

	id := t.fg(colorCyan).Bold(true).Render(v.ID)
	if v.IsKEV {
		id += " " + t.chip("KEV", colorMagenta)
	}
	if v.KEVRansomware {
		id += " " + t.chip("RANSOMWARE", colorMagenta)
	}
	id += "  " + t.bandFG(bnd).Bold(true).Render(bandLabel(bnd))
	b.WriteString(id + "\n")

	if v.CVSSScore != nil {
		line := indent + t.Label.Render("CVSS ") +
			t.bandBar(bnd, *v.CVSSScore/cvssMaxScore, colScoreBarW) + " " +
			t.bandFG(bnd).Bold(true).Render(cvssString(v.CVSSScore))
		if v.CVSSSeverity != "" {
			line += " " + t.Muted.Render(v.CVSSSeverity)
		}
		if v.CVSSVersion != "" {
			line += t.Dim.Render(" (v" + v.CVSSVersion + ")")
		}
		b.WriteString(line + "\n")
	}

	if v.EPSS != nil {
		eb := epssBand(v.EPSS)
		line := indent + t.Label.Render("EPSS ") + t.bandFG(eb).Bold(true).Render(epssString(v.EPSS))
		if v.EPSSPercentile != nil {
			line += t.Dim.Render(" (percentile ") + t.Muted.Render(epssString(v.EPSSPercentile)) + t.Dim.Render(")")
		}
		b.WriteString(line + "\n")
	}

	var meta []string
	if v.CWE != "" {
		meta = append(meta, t.Label.Render("CWE ")+t.Muted.Render(v.CWE))
	}
	if v.CVSSVector != "" {
		meta = append(meta, t.Dim.Render(v.CVSSVector))
	}
	if len(meta) > 0 {
		b.WriteString(indent + strings.Join(meta, t.Dim.Render(metaDivider)) + "\n")
	}

	if strings.TrimSpace(v.Description) != "" {
		b.WriteString(m.wrapIndent(v.Description, w, t.Muted) + "\n")
	}
	b.WriteString(indent + t.Link.Render(nvdBaseURL+v.ID) + "\n\n")
	return b.String()
}

func (m Model) wrapIndent(s string, w int, style lipgloss.Style) string {
	width := w - detailIndent
	if width < 1 {
		width = 1
	}
	wrapped := style.Width(width).Render(strings.TrimSpace(s))
	pad := strings.Repeat(" ", detailIndent)
	lines := strings.Split(wrapped, "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

func sortedArticles(c store.DigestCluster) []store.DigestArticle {
	out := make([]store.DigestArticle, len(c.Articles))
	copy(out, c.Articles)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PublishedAt != out[j].PublishedAt {
			return out[i].PublishedAt > out[j].PublishedAt
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (m Model) sortedDetailCVEs(c store.DigestCluster) []store.CVE {
	out := make([]store.CVE, 0, len(c.CVEs))
	for _, dc := range c.CVEs {
		if full, ok := m.cveDetail[dc.ID]; ok {
			out = append(out, full)
			continue
		}
		out = append(out, store.CVE{ID: dc.ID, CVSSScore: dc.CVSSScore, EPSS: dc.EPSS, IsKEV: dc.IsKEV})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsKEV != out[j].IsKEV {
			return out[i].IsKEV
		}
		if ci, cj := scoreOf(out[i].CVSSScore), scoreOf(out[j].CVSSScore); ci != cj {
			return ci > cj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func scoreOf(p *float64) float64 {
	if p == nil {
		return -1
	}
	return *p
}
