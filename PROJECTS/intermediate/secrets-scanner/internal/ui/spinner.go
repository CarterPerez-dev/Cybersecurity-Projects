// ©AngelaMos | 2026
// spinner.go

package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

var frames = []string{
	"\u280b", "\u2819", "\u2839", "\u2838",
	"\u283c", "\u2834", "\u2826", "\u2827",
	"\u2807", "\u280f",
}

type Spinner struct {
	msg    string
	done   chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
	active bool
}

func NewSpinner(msg string) *Spinner {
	return &Spinner{msg: msg}
}

func (s *Spinner) Start() {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return
	}
	s.active = true
	s.done = make(chan struct{})
	s.wg.Add(1)
	s.mu.Unlock()

	go s.run()
}

func (s *Spinner) Stop() {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	close(s.done)
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Spinner) run() {
	defer s.wg.Done()
	defer fmt.Print("\033[?25h")
	fmt.Print("\033[?25l")

	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()

	idx := 0
	for {
		select {
		case <-s.done:
			clearLine()
			fmt.Print("\033[?25h")
			return
		case <-ticker.C:
			frame := frames[idx%len(frames)]
			fmt.Printf(
				"\r  %s %s",
				CyanBold(frame),
				HiMagenta(s.msg),
			)
			idx++
		}
	}
}

func clearLine() {
	fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
}
