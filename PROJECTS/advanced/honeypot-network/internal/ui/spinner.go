/*
©AngelaMos | 2026
spinner.go

Terminal spinner for long-running operations
*/

package ui

import (
	"fmt"
	"sync"
	"time"
)

var frames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

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
		for {
			select {
			case <-s.stop:
				fmt.Printf("\r\033[K")
				return
			default:
				fmt.Printf(
					"\r  %s %s",
					Cyan(frames[i%len(frames)]),
					s.message,
				)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

func (s *Spinner) Stop() {
	close(s.stop)
	s.done.Wait()
}
