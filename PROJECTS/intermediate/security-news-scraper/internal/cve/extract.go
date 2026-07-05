// ©AngelaMos | 2026
// extract.go

package cve

import (
	"regexp"
	"sort"
	"strings"
)

var pattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

func Extract(texts ...string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, text := range texts {
		for _, match := range pattern.FindAllString(text, -1) {
			id := strings.ToUpper(match)
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
