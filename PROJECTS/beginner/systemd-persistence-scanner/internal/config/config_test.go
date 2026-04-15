/*
©AngelaMos | 2026
config_test.go
*/

package config

import (
	"testing"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func TestParseIgnoreFile(t *testing.T) {
	data := []byte(`# Sentinel ignore file
ignore:
  - path: /etc/systemd/system/docker.service
  - scanner: kernel
    title: Kernel module loaded at boot
  - path: /etc/cron.d/certbot
`)

	list, err := parseIgnoreFile(data)
	if err != nil {
		t.Fatalf("parseIgnoreFile: %v", err)
	}

	if len(list.Rules) != 3 {
		t.Fatalf(
			"rules count = %d, want 3",
			len(list.Rules),
		)
	}

	if list.Rules[0].Path != "/etc/systemd/system/docker.service" {
		t.Errorf(
			"rule[0].Path = %q",
			list.Rules[0].Path,
		)
	}

	if list.Rules[1].Scanner != "kernel" ||
		list.Rules[1].Title != "Kernel module loaded at boot" {
		t.Errorf(
			"rule[1] = %+v",
			list.Rules[1],
		)
	}

	if list.Rules[2].Path != "/etc/cron.d/certbot" {
		t.Errorf(
			"rule[2].Path = %q",
			list.Rules[2].Path,
		)
	}
}

func TestFilter_ByPath(t *testing.T) {
	list := IgnoreList{
		Rules: []IgnoreRule{
			{Path: "/etc/systemd/system/docker.service"},
		},
	}

	findings := []types.Finding{
		{
			Scanner: "systemd",
			Path:    "/etc/systemd/system/docker.service",
			Title:   "some finding",
		},
		{
			Scanner: "systemd",
			Path:    "/etc/systemd/system/evil.service",
			Title:   "another finding",
		},
	}

	filtered := list.Filter(findings)
	if len(filtered) != 1 {
		t.Fatalf(
			"filtered count = %d, want 1",
			len(filtered),
		)
	}
	if filtered[0].Path != "/etc/systemd/system/evil.service" {
		t.Errorf(
			"remaining finding path = %q",
			filtered[0].Path,
		)
	}
}

func TestFilter_ByScannerAndTitle(t *testing.T) {
	list := IgnoreList{
		Rules: []IgnoreRule{
			{
				Scanner: "kernel",
				Title:   "Kernel module loaded at boot",
			},
		},
	}

	findings := []types.Finding{
		{
			Scanner: "kernel",
			Title:   "Kernel module loaded at boot",
			Path:    "/etc/modules-load.d/loop.conf",
		},
		{
			Scanner: "kernel",
			Title:   "Module install hook runs shell command",
			Path:    "/etc/modprobe.d/evil.conf",
		},
	}

	filtered := list.Filter(findings)
	if len(filtered) != 1 {
		t.Fatalf(
			"filtered count = %d, want 1",
			len(filtered),
		)
	}
	if filtered[0].Title != "Module install hook runs shell command" {
		t.Errorf(
			"remaining finding title = %q",
			filtered[0].Title,
		)
	}
}

func TestFilter_EmptyList(t *testing.T) {
	list := IgnoreList{}
	findings := []types.Finding{
		{Scanner: "cron", Title: "test"},
	}

	filtered := list.Filter(findings)
	if len(filtered) != 1 {
		t.Fatalf(
			"empty ignore list should not filter: got %d",
			len(filtered),
		)
	}
}
