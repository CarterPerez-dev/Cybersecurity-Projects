// ©AngelaMos | 2026
// list.go

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/CarterPerez-dev/nadezhda/internal/rank"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

const (
	colSelBarW   = 1
	colRankW     = 2
	colScoreBarW = 10
	colScoreNumW = 4
	colOutletW   = 6
	colCVEW      = 5
	colGaps      = 6
	minHeadlineW = 12

	glyphSelected = "◆"
	glyphHot      = "▐"
	glyphOutlet   = "◉"
)

func (m Model) listView() string {
	header := m.listChrome()
	footer := m.listFooter()
	capacity := m.height - lipgloss.Height(header) - lipgloss.Height(footer)
	if capacity < 1 {
		capacity = 1
	}
	body := m.listBody(capacity)
	return lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
}

func (m Model) listChrome() string {
	right := m.theme.Meta.Render(fmt.Sprintf("%d stories", len(m.scored)))
	return lipgloss.JoinVertical(lipgloss.Left,
		m.spread(m.wordmark(), right),
		m.theme.rule(m.width),
		m.listColHeader(),
	)
}

func (m Model) listColHeader() string {
	t := m.theme.ColHead
	left := strings.Join([]string{
		" ",
		fmt.Sprintf("%*s", colRankW, "#"),
		padRight("STORY", m.headlineWidth()),
		padRight("SCORE", colScoreBarW),
		fmt.Sprintf("%*s", colScoreNumW, ""),
		padRight("OUT", colOutletW),
	}, " ")
	return m.spread(t.Render(left), t.Render("CVE"))
}

func (m Model) listFooter() string {
	keys := m.keyHints(m.keys.Up, m.keys.Down, m.keys.Open, m.keys.Browser, m.keys.Quit)
	right := m.severityLegend()
	if s := m.statusText(); s != "" {
		right = s
	}
	return lipgloss.JoinVertical(lipgloss.Left,
		m.theme.rule(m.width),
		m.spread(keys, right),
	)
}

func (m Model) listBody(capacity int) string {
	if len(m.scored) == 0 {
		return m.emptyBody(capacity)
	}
	first, last := windowRange(m.cursor, capacity, len(m.scored))
	lines := make([]string, 0, capacity)
	for i := first; i < last; i++ {
		lines = append(lines, m.renderRow(i, m.scored[i], i == m.cursor))
	}
	for len(lines) < capacity {
		lines = append(lines, "")
	}
	return strings.Join(lines, "\n")
}

func (m Model) emptyBody(capacity int) string {
	t := m.theme
	msg := t.Muted.Render("no stories in the store yet — run ") +
		t.KeyGlyph.Render("nadezhda scrape")
	return lipgloss.Place(m.width, capacity, lipgloss.Center, lipgloss.Center, msg)
}

func (m Model) renderRow(i int, s rank.Scored, selected bool) string {
	t := m.theme
	c := s.Cluster
	b := clusterBand(c)
	kev := clusterHasKEV(c)

	barStyle := t.Dim
	barGlyph := " "
	switch {
	case selected:
		barGlyph, barStyle = glyphSelected, t.SelBar
	case kev || b == bandCritical:
		barGlyph, barStyle = glyphHot, t.bandFG(bandCritical)
	case b != bandNone:
		barGlyph, barStyle = glyphHot, t.bandFG(b)
	}

	rankStyle := t.Rank
	headStyle := t.Headline
	if selected {
		rankStyle, headStyle = t.RankSel, t.HeadlineSel
	}

	hlW := m.headlineWidth()
	left := strings.Join([]string{
		barStyle.Render(barGlyph),
		rankStyle.Render(fmt.Sprintf("%*d", colRankW, i+1)),
		headStyle.Render(padRight(truncate(headlineOf(c), hlW), hlW)),
		t.spectrumBar(s.Score, colScoreBarW),
		t.Meta.Render(fmt.Sprintf("%*s", colScoreNumW, fmt.Sprintf("%.2f", s.Score))),
		m.renderOutlets(c),
	}, " ")
	return m.spread(left, m.renderCVEChip(c, b, kev))
}

func windowRange(cursor, capacity, total int) (int, int) {
	if capacity < 1 {
		capacity = 1
	}
	first := 0
	if cursor >= capacity {
		first = cursor - capacity + 1
	}
	last := first + capacity
	if last > total {
		last = total
	}
	return first, last
}

func (m Model) renderOutlets(c store.DigestCluster) string {
	n := outletCount(c)
	dots := n
	if dots > colOutletW {
		dots = colOutletW
	}
	styled := m.theme.fg(outletColor(n)).Render(strings.Repeat(glyphOutlet, dots))
	if pad := colOutletW - dots; pad > 0 {
		styled += strings.Repeat(" ", pad)
	}
	return styled
}

func (m Model) renderCVEChip(c store.DigestCluster, b band, kev bool) string {
	t := m.theme
	if kev {
		return t.chip("KEV", colorMagenta)
	}
	if max := clusterMaxCVSS(c); max != nil {
		return t.bandFG(b).Bold(true).Render(cvssString(max))
	}
	if len(c.CVEs) > 0 {
		return t.Dim.Render("cve")
	}
	return t.Dim.Render(emptyMarker)
}

func (m Model) headlineWidth() int {
	fixed := colSelBarW + colRankW + colScoreBarW + colScoreNumW + colOutletW + colCVEW + colGaps
	if w := m.width - fixed; w > minHeadlineW {
		return w
	}
	return minHeadlineW
}

func headlineArticle(c store.DigestCluster) store.DigestArticle {
	var best store.DigestArticle
	for i, a := range c.Articles {
		if i == 0 || a.PublishedAt > best.PublishedAt ||
			(a.PublishedAt == best.PublishedAt && a.ID < best.ID) {
			best = a
		}
	}
	return best
}

func headlineOf(c store.DigestCluster) string {
	if a := headlineArticle(c); strings.TrimSpace(a.Title) != "" {
		return a.Title
	}
	return "(untitled cluster)"
}

func outletCount(c store.DigestCluster) int {
	seen := make(map[string]struct{}, len(c.Articles))
	for _, a := range c.Articles {
		seen[a.SourceName] = struct{}{}
	}
	return len(seen)
}

func outletColor(n int) string {
	switch {
	case n >= 4:
		return colorViolet
	case n == 3:
		return colorCyan
	case n == 2:
		return colorBlue
	default:
		return colorDim
	}
}
