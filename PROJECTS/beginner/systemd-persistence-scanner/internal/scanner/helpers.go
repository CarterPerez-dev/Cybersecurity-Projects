/*
©AngelaMos | 2026
helpers.go

Shared filesystem utilities used by all scanner modules

Provides safe file reading, directory listing, line scanning, and
file-age checking functions. Handles permission errors gracefully
by returning empty results rather than propagating errors, since
scanners should skip inaccessible paths without aborting the run.
*/

package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

func ReadLines(path string) []string {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func ListDir(dir string) []os.DirEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	return entries
}

func ListFiles(dir string) []string {
	entries := ListDir(dir)
	var paths []string
	for _, e := range entries {
		if !e.IsDir() {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths
}

func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func IsWorldWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0o002 != 0
}

func ModifiedWithin(path string, d time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < d
}

func ResolveRoot(root, path string) string {
	if root == "/" {
		return path
	}
	return filepath.Join(root, path)
}

func FindUserDirs(root string) []string {
	homeBase := ResolveRoot(root, "/home")
	entries := ListDir(homeBase)
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(
				dirs,
				filepath.Join(homeBase, e.Name()),
			)
		}
	}

	rootHome := ResolveRoot(root, "/root")
	if FileExists(rootHome) {
		dirs = append(dirs, rootHome)
	}
	return dirs
}

func IsCommentOrEmpty(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

func ScanFileForPatterns(
	path, scannerName, mitre string,
) []types.Finding {
	lines := ReadLines(path)
	var findings []types.Finding

	for _, line := range lines {
		if IsCommentOrEmpty(line) {
			continue
		}
		matched, sev, label := MatchLine(line)
		if matched {
			findings = append(findings, types.Finding{
				Scanner:  scannerName,
				Severity: sev,
				Title:    label,
				Path:     path,
				Evidence: strings.TrimSpace(line),
				MITRE:    mitre,
			})
		}
	}
	return findings
}

func containsShellCommand(line string) bool {
	shells := []string{
		"/bin/sh", "/bin/bash", "/bin/zsh",
		"/usr/bin/sh", "/usr/bin/bash",
	}
	for _, sh := range shells {
		if strings.Contains(line, sh) {
			return true
		}
	}
	return NetworkToolPattern.MatchString(line) ||
		ScriptLangPattern.MatchString(line)
}
