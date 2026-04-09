// ©AngelaMos | 2026
// spinner.go

package ui

import (
	"fmt"
	"sync"
	"time"
)

var spinChars = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type Spinner struct {
	message string
	stop    chan struct{}
	done    sync.WaitGroup
}

func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		stop:    make(chan struct{}),
	}
}

func (s *Spinner) Start() {
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stop:
				fmt.Print("\r\033[K")
				return
			case <-ticker.C:
				fmt.Printf("\r  %s %s", Cyan(spinChars[i%len(spinChars)]), s.message)
				i++
			}
		}
	}()
}

func (s *Spinner) Stop() {
	close(s.stop)
	s.done.Wait()
}
