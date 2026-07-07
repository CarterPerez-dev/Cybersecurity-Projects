// ©AngelaMos | 2026
// view.go

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/lipgloss"
)

const (
	brandName = "NADEZHDA"
	tagline   = "THREAT.WIRE"

	markOpen  = "◤ "
	markClose = " ◢"
	markMid   = "═◆═"

	errWrapMax    = 80
	errWrapMin    = 20
	errWrapMargin = 6

	minRenderWidth  = 44
	minRenderHeight = 10
)

func (m Model) View() string {
	if m.width < minRenderWidth || m.height < minRenderHeight {
		return m.tooSmallView()
	}
	switch m.state {
	case stateLoading:
		return m.loadingView()
	case stateError:
		return m.errorView()
	case stateDetail:
		return m.detailView()
	default:
		return m.listView()
	}
}

func (m Model) tooSmallView() string {
	w, h := m.width, m.height
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	msg := m.theme.Muted.Render(fmt.Sprintf("terminal too small — need at least %dx%d", minRenderWidth, minRenderHeight))
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, msg)
}

func (m Model) wordmark() string {
	t := m.theme
	return t.BrandMark.Render(markOpen) + t.Brand.Render(brandName) + t.BrandMark.Render(markClose) +
		" " + t.fg(colorCyan).Render(markMid) + " " + t.fg(colorViolet).Render(tagline) + " " + t.fg(colorCyan).Render(markMid)
}

func (m Model) spread(left, right string) string {
	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func (m Model) keyHints(bindings ...key.Binding) string {
	t := m.theme
	parts := make([]string, 0, len(bindings))
	for _, b := range bindings {
		h := b.Help()
		parts = append(parts, t.KeyGlyph.Render(h.Key)+" "+t.KeyDesc.Render(h.Desc))
	}
	return strings.Join(parts, t.Dim.Render(" · "))
}

func (m Model) severityLegend() string {
	t := m.theme
	item := func(color, label string) string {
		return t.fg(color).Render("■") + " " + t.KeyDesc.Render(label)
	}
	return strings.Join([]string{
		item(colorMagenta, "KEV/CRIT"),
		item(colorAmber, "HIGH"),
		item(colorYellow, "MED"),
		item(colorCyan, "LOW"),
	}, "  ")
}

func (m Model) loadingView() string {
	t := m.theme
	brand := t.BrandMark.Render(markOpen) + t.Brand.Render(brandName) + t.BrandMark.Render(markClose)
	tag := t.fg(colorViolet).Render(tagline)
	line := m.spinner.View() + " " + t.Meta.Render("assembling threat wire") + " " + m.spinner.View()
	block := lipgloss.JoinVertical(lipgloss.Center, brand, tag, "", line)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, block)
}

func (m Model) errorView() string {
	t := m.theme
	title := t.fg(colorMagenta).Bold(true).Render("▚ WIRE FAULT ▞")
	block := lipgloss.JoinVertical(lipgloss.Center,
		title,
		"",
		m.errString(),
		"",
		t.KeyDesc.Render("press ")+t.KeyGlyph.Render("q")+t.KeyDesc.Render(" to quit"),
	)
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, block)
}

func (m Model) errString() string {
	if m.err == nil {
		return m.theme.Text.Render("unknown fault")
	}
	w := m.width - errWrapMargin
	if w > errWrapMax {
		w = errWrapMax
	}
	if w < errWrapMin {
		w = errWrapMin
	}
	return m.theme.Text.Width(w).Align(lipgloss.Center).Render(m.err.Error())
}

func (m Model) detailView() string {
	t := m.theme
	scroll := fmt.Sprintf("%3.0f%%", m.viewport.ScrollPercent()*100)
	left := t.PanelTitle.Render(markOpen+"DOSSIER"+markClose) + " " +
		t.Muted.Render(fmt.Sprintf("story %d of %d", m.cursor+1, len(m.scored)))
	head := m.spread(left, t.Meta.Render(scroll))
	foot := m.spread(
		m.keyHints(m.keys.Back, m.keys.Browser, m.keys.Ideate, m.keys.Down, m.keys.Up, m.keys.Quit),
		m.statusText(),
	)
	return lipgloss.JoinVertical(lipgloss.Left,
		head,
		t.rule(m.width),
		m.viewport.View(),
		t.rule(m.width),
		foot,
	)
}

func (m Model) statusText() string {
	if m.generating {
		return m.spinner.View() + " " + m.theme.fg(colorCyan).Render(m.status)
	}
	if m.status == "" {
		return ""
	}
	color := colorCyan
	if m.statusErr {
		color = colorMagenta
	}
	return m.theme.fg(color).Render(m.status)
}
