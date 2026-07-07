// ©AngelaMos | 2026
// model_test.go

package tui

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/CarterPerez-dev/nadezhda/internal/ai"
	"github.com/CarterPerez-dev/nadezhda/internal/rank"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

func testNow() time.Time { return time.Unix(1_720_000_000, 0) }

func runeKey(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

func sampleData() Data {
	now := testNow().Unix()
	c1 := store.DigestCluster{
		ClusterID: 1,
		Key:       "log4shell",
		Size:      2,
		FirstSeen: now - 3600,
		LastSeen:  now - 600,
		Articles: []store.DigestArticle{
			{ID: 1, SourceName: "krebs", SourceWeight: 1.0, Title: "Log4Shell RCE exploited in the wild", CanonicalURL: "https://krebsonsecurity.com/log4shell", PublishedAt: now - 600},
			{ID: 2, SourceName: "theregister", SourceWeight: 0.9, Title: "Log4j flaw under active attack", CanonicalURL: "https://theregister.com/log4j", PublishedAt: now - 3600},
		},
		CVEs: []store.DigestCVE{
			{ID: "CVE-2021-44228", CVSSScore: ptr(10.0), EPSS: ptr(0.97), IsKEV: true},
		},
	}
	c2 := store.DigestCluster{
		ClusterID: 2,
		Key:       "policy",
		Size:      1,
		FirstSeen: now - 7200,
		LastSeen:  now - 7200,
		Articles: []store.DigestArticle{
			{ID: 3, SourceName: "darkreading", SourceWeight: 0.7, Title: "New disclosure guidelines published", CanonicalURL: "https://darkreading.com/policy", PublishedAt: now - 7200},
		},
	}
	scored := []rank.Scored{{Cluster: c1, Score: 0.94}, {Cluster: c2, Score: 0.42}}
	detail := map[string]store.CVE{
		"CVE-2021-44228": {
			ID:           "CVE-2021-44228",
			Description:  "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints.",
			CVSSScore:    ptr(10.0),
			CVSSVersion:  "3.1",
			CVSSSeverity: "CRITICAL",
			CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			CWE:          "CWE-502",
			IsKEV:        true,
			EPSS:         ptr(0.97),
		},
	}
	return Data{Scored: scored, CVEDetail: detail}
}

func toModel(t *testing.T, tm tea.Model) Model {
	t.Helper()
	m, ok := tm.(Model)
	if !ok {
		t.Fatalf("Update returned %T, want tui.Model", tm)
	}
	return m
}

func step(t *testing.T, m Model, msg tea.Msg) Model {
	t.Helper()
	tm, _ := m.Update(msg)
	return toModel(t, tm)
}

func loadedModel(t *testing.T) Model {
	t.Helper()
	return step(t, New(nil, nil, testNow()), dataMsg{sampleData()})
}

func TestInitialStateIsLoading(t *testing.T) {
	if m := New(nil, nil, testNow()); m.state != stateLoading {
		t.Fatalf("initial state = %v, want stateLoading", m.state)
	}
}

func TestDataMsgTransitionsToList(t *testing.T) {
	m := loadedModel(t)
	if m.state != stateList {
		t.Fatalf("state = %v, want stateList", m.state)
	}
	if len(m.scored) != 2 {
		t.Fatalf("len(scored) = %d, want 2", len(m.scored))
	}
}

func TestErrMsgTransitionsToError(t *testing.T) {
	m := step(t, New(nil, nil, testNow()), errMsg{errors.New("wire down")})
	if m.state != stateError {
		t.Fatalf("state = %v, want stateError", m.state)
	}
	if m.err == nil {
		t.Fatal("err = nil, want non-nil")
	}
}

func TestListNavigationClamps(t *testing.T) {
	m := loadedModel(t)
	m = step(t, m, runeKey('j'))
	if m.cursor != 1 {
		t.Fatalf("after down, cursor = %d, want 1", m.cursor)
	}
	m = step(t, m, runeKey('j'))
	if m.cursor != 1 {
		t.Fatalf("after down past end, cursor = %d, want 1", m.cursor)
	}
	m = step(t, m, runeKey('k'))
	if m.cursor != 0 {
		t.Fatalf("after up, cursor = %d, want 0", m.cursor)
	}
	m = step(t, m, runeKey('k'))
	if m.cursor != 0 {
		t.Fatalf("after up past start, cursor = %d, want 0", m.cursor)
	}
}

func TestListTopBottom(t *testing.T) {
	m := loadedModel(t)
	m = step(t, m, runeKey('G'))
	if m.cursor != 1 {
		t.Fatalf("after G, cursor = %d, want 1", m.cursor)
	}
	m = step(t, m, runeKey('g'))
	if m.cursor != 0 {
		t.Fatalf("after g, cursor = %d, want 0", m.cursor)
	}
}

func TestOpenAndBack(t *testing.T) {
	m := loadedModel(t)
	m = step(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.state != stateDetail {
		t.Fatalf("after enter, state = %v, want stateDetail", m.state)
	}
	m = step(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.state != stateList {
		t.Fatalf("after esc, state = %v, want stateList", m.state)
	}
}

func TestQuitReturnsQuitCmd(t *testing.T) {
	m := loadedModel(t)
	_, cmd := m.Update(runeKey('q'))
	if cmd == nil {
		t.Fatal("quit returned nil cmd")
	}
	if reflect.TypeOf(cmd()) != reflect.TypeOf(tea.Quit()) {
		t.Fatalf("quit cmd yielded %T, want tea.QuitMsg", cmd())
	}
}

func TestWindowSizeSizesViewport(t *testing.T) {
	m := loadedModel(t)
	m = step(t, m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if m.width != 120 || m.height != 40 {
		t.Fatalf("size = %dx%d, want 120x40", m.width, m.height)
	}
	if m.viewport.Width != 120 {
		t.Fatalf("viewport.Width = %d, want 120", m.viewport.Width)
	}
	if m.viewport.Height != 40-detailChrome {
		t.Fatalf("viewport.Height = %d, want %d", m.viewport.Height, 40-detailChrome)
	}
}

func TestSpinnerTickIgnoredOutsideLoading(t *testing.T) {
	m := loadedModel(t)
	m = step(t, m, spinner.TickMsg{})
	if m.state != stateList {
		t.Fatalf("spinner tick changed state to %v, want stateList", m.state)
	}
}

func TestViewsRenderNonEmpty(t *testing.T) {
	loading := New(nil, nil, testNow())
	if strings.TrimSpace(loading.View()) == "" {
		t.Error("loading view is empty")
	}

	list := loadedModel(t)
	lv := list.View()
	if !strings.Contains(lv, "NADEZHDA") {
		t.Error("list view missing brand")
	}
	if !strings.Contains(lv, "Log4Shell") {
		t.Error("list view missing headline")
	}

	detail := step(t, list, tea.KeyMsg{Type: tea.KeyEnter})
	dv := detail.View()
	if !strings.Contains(dv, "CVE-2021-44228") {
		t.Error("detail view missing CVE id")
	}
	if !strings.Contains(dv, "CRITICAL") {
		t.Error("detail view missing severity label")
	}

	errv := step(t, New(nil, nil, testNow()), errMsg{errors.New("boom")})
	if strings.TrimSpace(errv.View()) == "" {
		t.Error("error view is empty")
	}
}

func TestEmptyStoreRendersHint(t *testing.T) {
	m := step(t, New(nil, nil, testNow()), dataMsg{Data{}})
	if m.state != stateList {
		t.Fatalf("state = %v, want stateList", m.state)
	}
	if !strings.Contains(m.View(), "scrape") {
		t.Error("empty list view missing scrape hint")
	}
}

func TestTooSmallTerminal(t *testing.T) {
	m := step(t, loadedModel(t), tea.WindowSizeMsg{Width: 20, Height: 5})
	if !strings.Contains(m.View(), "too small") {
		t.Error("tiny terminal did not render the too-small notice")
	}
}

func TestWindowRange(t *testing.T) {
	cases := []struct {
		cursor, capacity, total int
		first, last             int
	}{
		{0, 5, 10, 0, 5},
		{4, 5, 10, 0, 5},
		{5, 5, 10, 1, 6},
		{9, 5, 10, 5, 10},
		{0, 5, 3, 0, 3},
		{2, 5, 3, 0, 3},
		{0, 0, 10, 0, 1},
		{7, 3, 10, 5, 8},
	}
	for _, c := range cases {
		first, last := windowRange(c.cursor, c.capacity, c.total)
		if first != c.first || last != c.last {
			t.Errorf("windowRange(%d, %d, %d) = (%d, %d), want (%d, %d)",
				c.cursor, c.capacity, c.total, first, last, c.first, c.last)
		}
		if c.cursor < c.total && (c.cursor < first || c.cursor >= last) {
			t.Errorf("windowRange(%d, %d, %d) window [%d,%d) excludes cursor",
				c.cursor, c.capacity, c.total, first, last)
		}
	}
}

func TestHeadlineFreshest(t *testing.T) {
	fresh := store.DigestCluster{Articles: []store.DigestArticle{
		{ID: 1, Title: "older", PublishedAt: 100},
		{ID: 2, Title: "newest", PublishedAt: 300},
		{ID: 3, Title: "mid", PublishedAt: 200},
	}}
	if got := headlineOf(fresh); got != "newest" {
		t.Errorf("headlineOf(fresh) = %q, want newest", got)
	}
	tie := store.DigestCluster{Articles: []store.DigestArticle{
		{ID: 5, Title: "high-id", PublishedAt: 300},
		{ID: 2, Title: "low-id", PublishedAt: 300},
	}}
	if got := headlineOf(tie); got != "low-id" {
		t.Errorf("headlineOf(tie) = %q, want low-id (lowest id on equal time)", got)
	}
	if got := headlineOf(store.DigestCluster{}); got != "(untitled cluster)" {
		t.Errorf("headlineOf(empty) = %q, want (untitled cluster)", got)
	}
}

func TestOpenInBrowser(t *testing.T) {
	m := loadedModel(t)
	var opened string
	m.opener = func(u string) error { opened = u; return nil }

	tm, cmd := m.Update(runeKey('o'))
	m = toModel(t, tm)
	if cmd == nil {
		t.Fatal("pressing o produced no command")
	}
	msg := cmd()
	if opened != "https://krebsonsecurity.com/log4shell" {
		t.Fatalf("opened %q, want the selected cluster's headline url", opened)
	}
	om, ok := msg.(openedMsg)
	if !ok {
		t.Fatalf("open cmd returned %T, want openedMsg", msg)
	}
	m = step(t, m, om)
	if m.status == "" || m.statusErr {
		t.Errorf("after open: status=%q err=%v, want a success status", m.status, m.statusErr)
	}
	if !strings.Contains(m.View(), m.status) {
		t.Error("open status not shown in the view")
	}
	m = step(t, m, runeKey('j'))
	if m.status != "" {
		t.Error("status should clear on the next keypress")
	}
}

func TestOpenURLRejectsNonHTTP(t *testing.T) {
	for _, bad := range []string{"file:///etc/passwd", "javascript:alert(1)", "", "ftp://x/y"} {
		if err := openURL(bad); err == nil {
			t.Errorf("openURL(%q) = nil, want refusal", bad)
		}
	}
}

func TestIdeateDisabledShowsHint(t *testing.T) {
	m := loadedModel(t)
	m = step(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = step(t, m, runeKey('i'))
	if !m.statusErr || !strings.Contains(m.status, "nadezhda ai") {
		t.Errorf("i with nil ideator: status=%q err=%v, want a setup hint", m.status, m.statusErr)
	}
	if m.generating {
		t.Error("generating should stay false when ideator is nil")
	}
}

func TestIdeateIgnoredInListView(t *testing.T) {
	m := loadedModel(t)
	m.ideator = func(c store.DigestCluster) (ai.IdeationResult, error) {
		return ai.IdeationResult{Summary: "s", Angles: []string{"a"}, Format: "blog"}, nil
	}
	tm, cmd := m.Update(runeKey('i'))
	m = toModel(t, tm)
	if m.generating || cmd != nil {
		t.Errorf("i in the list must be a no-op: generating=%v cmd=%v", m.generating, cmd)
	}
}

func TestIdeateFlowStoresAndRenders(t *testing.T) {
	m := loadedModel(t)
	m.ideator = func(c store.DigestCluster) (ai.IdeationResult, error) {
		return ai.IdeationResult{Summary: "s", Why: "w", Angles: []string{"angle-one", "angle-two"}, Format: "video"}, nil
	}
	m = step(t, m, tea.KeyMsg{Type: tea.KeyEnter})

	tm, cmd := m.Update(runeKey('i'))
	m = toModel(t, tm)
	if !m.generating || cmd == nil {
		t.Fatalf("after i: generating=%v cmd=%v", m.generating, cmd)
	}

	msg := m.ideateSelected()()
	im, ok := msg.(ideatedMsg)
	if !ok {
		t.Fatalf("ideateSelected produced %T, want ideatedMsg", msg)
	}
	if im.clusterID != 1 || im.result.Summary != "s" {
		t.Fatalf("ideatedMsg = %+v", im)
	}

	m = step(t, m, im)
	if m.generating {
		t.Error("generating still true after ideatedMsg")
	}
	if m.notes[1].Summary != "s" || len(m.notes[1].Angles) != 2 {
		t.Errorf("note not stored: %+v", m.notes[1])
	}

	m = step(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	dv := m.View()
	if !strings.Contains(dv, "AI IDEAS") || !strings.Contains(dv, "angle-one") {
		t.Error("detail view missing the ideation section")
	}
}

func TestIdeateErrorSetsStatus(t *testing.T) {
	m := loadedModel(t)
	m.ideator = func(c store.DigestCluster) (ai.IdeationResult, error) {
		return ai.IdeationResult{}, errors.New("boom")
	}
	m = step(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = step(t, m, runeKey('i'))
	msg := m.ideateSelected()()
	em, ok := msg.(ideateErrMsg)
	if !ok {
		t.Fatalf("ideateSelected produced %T, want ideateErrMsg", msg)
	}
	m = step(t, m, em)
	if m.generating {
		t.Error("generating still true after ideateErrMsg")
	}
	if !m.statusErr {
		t.Error("statusErr not set after ideate failure")
	}
}
