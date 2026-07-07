// ©AngelaMos | 2026
// model.go

package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/CarterPerez-dev/nadezhda/internal/ai"
	"github.com/CarterPerez-dev/nadezhda/internal/rank"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

type viewState int

const (
	stateLoading viewState = iota
	stateList
	stateDetail
	stateError
)

const (
	defaultWidth  = 100
	defaultHeight = 32
	detailChrome  = 4
	spinnerFPS    = time.Second / 10
)

var raveSpinner = spinner.Spinner{
	Frames: []string{"◇", "◈", "◆", "◈", "◇", "·"},
	FPS:    spinnerFPS,
}

type Data struct {
	Scored    []rank.Scored
	CVEDetail map[string]store.CVE
	Notes     map[int64]ai.IdeationResult
}

type Loader func() (Data, error)

type dataMsg struct{ data Data }

type errMsg struct{ err error }

type openedMsg struct {
	url string
	err error
}

type Ideator func(store.DigestCluster) (ai.IdeationResult, error)

type ideatedMsg struct {
	clusterID int64
	result    ai.IdeationResult
}

type ideateErrMsg struct{ err error }

type Model struct {
	state    viewState
	loader   Loader
	now      time.Time
	theme    Theme
	keys     keyMap
	spinner  spinner.Model
	viewport viewport.Model

	width  int
	height int

	scored    []rank.Scored
	cveDetail map[string]store.CVE

	cursor int
	err    error

	opener    func(string) error
	status    string
	statusErr bool

	ideator    Ideator
	generating bool
	notes      map[int64]ai.IdeationResult
}

func New(loader Loader, ideator Ideator, now time.Time) Model {
	th := NewTheme()
	sp := spinner.New(spinner.WithSpinner(raveSpinner), spinner.WithStyle(th.Spinner))
	m := Model{
		state:     stateLoading,
		loader:    loader,
		now:       now,
		theme:     th,
		keys:      defaultKeyMap(),
		spinner:   sp,
		viewport:  viewport.New(defaultWidth, defaultHeight-detailChrome),
		width:     defaultWidth,
		height:    defaultHeight,
		cveDetail: map[string]store.CVE{},
		opener:    openURL,
		ideator:   ideator,
		notes:     map[int64]ai.IdeationResult{},
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.load())
}

func (m Model) load() tea.Cmd {
	loader := m.loader
	return func() tea.Msg {
		data, err := loader()
		if err != nil {
			return errMsg{err}
		}
		return dataMsg{data}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.applySize(msg.Width, msg.Height)
		return m, nil
	case dataMsg:
		m.scored = msg.data.Scored
		m.cveDetail = msg.data.CVEDetail
		if msg.data.Notes != nil {
			m.notes = msg.data.Notes
		}
		m.state = stateList
		return m, nil
	case errMsg:
		m.state = stateError
		m.err = msg.err
		return m, nil
	case openedMsg:
		if msg.err != nil {
			m.status, m.statusErr = "open failed: "+msg.err.Error(), true
		} else {
			m.status, m.statusErr = "opened in browser", false
		}
		return m, nil
	case ideatedMsg:
		m.generating = false
		m.notes[msg.clusterID] = msg.result
		m.status, m.statusErr = "ideas ready", false
		if m.state == stateDetail {
			m.viewport.SetContent(m.renderDetailBody())
			m.viewport.GotoBottom()
		}
		return m, nil
	case ideateErrMsg:
		m.generating = false
		m.status, m.statusErr = "ideate failed: "+msg.err.Error(), true
		return m, nil
	case spinner.TickMsg:
		if m.state != stateLoading && !m.generating {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	if m.state == stateDetail {
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	m.status = ""
	if key.Matches(msg, m.keys.Quit) {
		return m, tea.Quit
	}
	if key.Matches(msg, m.keys.Browser) && (m.state == stateList || m.state == stateDetail) {
		return m, m.openSelected()
	}
	if key.Matches(msg, m.keys.Ideate) && m.state == stateDetail {
		return m.startIdeate()
	}
	switch m.state {
	case stateList:
		return m.handleListKey(msg)
	case stateDetail:
		return m.handleDetailKey(msg)
	default:
		return m, nil
	}
}

func (m Model) openSelected() tea.Cmd {
	target := headlineArticle(m.selected().Cluster).CanonicalURL
	if target == "" {
		return nil
	}
	open := m.opener
	return func() tea.Msg {
		return openedMsg{url: target, err: open(target)}
	}
}

func (m Model) startIdeate() (tea.Model, tea.Cmd) {
	if m.ideator == nil {
		m.status, m.statusErr = "AI not set up — run: nadezhda ai", true
		return m, nil
	}
	if m.generating || len(m.scored) == 0 {
		return m, nil
	}
	m.generating = true
	m.status, m.statusErr = "ideating "+headlineOf(m.selected().Cluster), false
	return m, tea.Batch(m.ideateSelected(), m.spinner.Tick)
}

func (m Model) ideateSelected() tea.Cmd {
	ideator := m.ideator
	cluster := m.selected().Cluster
	return func() tea.Msg {
		res, err := ideator(cluster)
		if err != nil {
			return ideateErrMsg{err}
		}
		return ideatedMsg{clusterID: cluster.ClusterID, result: res}
	}
}

func (m Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(msg, m.keys.Down):
		if m.cursor < len(m.scored)-1 {
			m.cursor++
		}
	case key.Matches(msg, m.keys.Top):
		m.cursor = 0
	case key.Matches(msg, m.keys.Bottom):
		if len(m.scored) > 0 {
			m.cursor = len(m.scored) - 1
		}
	case key.Matches(msg, m.keys.Open):
		if len(m.scored) > 0 {
			m.state = stateDetail
			m.viewport.SetContent(m.renderDetailBody())
			m.viewport.GotoTop()
		}
	}
	return m, nil
}

func (m Model) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.Matches(msg, m.keys.Back) {
		m.state = stateList
		return m, nil
	}
	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m *Model) applySize(w, h int) {
	m.width = w
	m.height = h
	m.viewport.Width = m.bodyWidth()
	m.viewport.Height = m.detailBodyHeight()
	if m.state == stateDetail {
		m.viewport.SetContent(m.renderDetailBody())
	}
}

func (m Model) bodyWidth() int {
	if m.width > 1 {
		return m.width
	}
	return 1
}

func (m Model) detailBodyHeight() int {
	if h := m.height - detailChrome; h > 1 {
		return h
	}
	return 1
}

func (m Model) selected() rank.Scored {
	if m.cursor < 0 || m.cursor >= len(m.scored) {
		return rank.Scored{}
	}
	return m.scored[m.cursor]
}

func Run(loader Loader, ideator Ideator) error {
	m := New(loader, ideator, time.Now())
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

var _ tea.Model = Model{}
