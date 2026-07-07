// ©AngelaMos | 2026
// browser.go

package tui

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"

	"github.com/CarterPerez-dev/nadezhda/internal/setup"
)

func openURL(target string) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("refusing to open non-http url: %q", target)
	}
	name, args := openerCommand(target)
	cmd := exec.Command(name, args...)
	cmd.Env = setup.NonSecretEnviron()
	return cmd.Start()
}

func openerCommand(target string) (string, []string) {
	switch runtime.GOOS {
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", target}
	case "darwin":
		return "open", []string{target}
	default:
		return "xdg-open", []string{target}
	}
}
