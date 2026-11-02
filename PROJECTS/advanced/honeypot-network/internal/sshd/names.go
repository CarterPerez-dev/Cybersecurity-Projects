/*
©AngelaMos | 2026
names.go

Names and modes the emulated shell and filesystem share
*/

package sshd

const (
	rootHome = "/root"

	modeFileRW = "-rw-r--r--"
	modeFileRO = "-r--r--r--"

	cmdHostname = "hostname"
	cmdWget     = "wget"
	cmdExit     = "exit"

	fileHostname = "hostname"

	eventFieldHostname = "hostname"
)
