/*
©AngelaMos | 2026
patterns.go

Compiled regular expressions for detecting suspicious persistence content

Centralizes all pattern matching used across scanner modules so each
scanner does not duplicate regex compilation. Patterns cover network
tool invocations, encoding/obfuscation, reverse shell signatures,
temporary directory references, and alias hijacking.
*/

package scanner

import (
	"regexp"

	"github.com/CarterPerez-dev/sentinel/pkg/types"
)

var NetworkToolPattern = regexp.MustCompile(
	`\b(curl|wget|nc|ncat|nmap|socat)\b`,
)

var DownloadExecPattern = regexp.MustCompile(
	`(curl|wget)\s+.*\|\s*(bash|sh|zsh|dash)` +
		`|` +
		`(curl|wget)\s+.*-o\s+/tmp/`,
)

var EncodingPattern = regexp.MustCompile(
	`\b(base64\s+-d|base64\s+--decode|xxd\s+-r|openssl\s+enc)\b` +
		`|` +
		`\becho\s+[A-Za-z0-9+/=]{20,}\s*\|`,
)

var ReverseShellPattern = regexp.MustCompile(
	`/dev/tcp/` +
		`|` +
		`\bmkfifo\b.*\bnc\b` +
		`|` +
		`\bsocat\b.*\bexec\b` +
		`|` +
		`python[23]?\s+-c\s+.*socket` +
		`|` +
		`perl\s+-e\s+.*socket` +
		`|` +
		`ruby\s+-rsocket`,
)

var TempDirPattern = regexp.MustCompile(
	`(/tmp/|/dev/shm/|/var/tmp/)`,
)

var ScriptLangPattern = regexp.MustCompile(
	`\b(python[23]?|perl|ruby)\s+-[ce]\b`,
)

var AliasHijackPattern = regexp.MustCompile(
	`alias\s+(sudo|su|ssh|ls|cat|id|whoami|passwd)\s*=`,
)

var LDPreloadPattern = regexp.MustCompile(
	`\b(LD_PRELOAD|LD_LIBRARY_PATH)\s*=`,
)

var PathManipPattern = regexp.MustCompile(
	`\bPATH\s*=\s*["']?(/tmp|/dev/shm|/var/tmp)`,
)

var NohupPattern = regexp.MustCompile(
	`\bnohup\b.*&` +
		`|` +
		`&\s*disown`,
)

var EvalExecPattern = regexp.MustCompile(
	`\b(eval|exec)\s+["']?\$\(.*(curl|wget|nc|base64)`,
)

var SuidPattern = regexp.MustCompile(
	`chmod\s+[ugo]*\+s\b` +
		`|` +
		`chmod\s+[247][0-7]{3}\b`,
)

var AccountCreatePattern = regexp.MustCompile(
	`\b(useradd|adduser|usermod)\b`,
)

var ImmutablePattern = regexp.MustCompile(
	`\bchattr\s+[+-]i\b`,
)

var PersistenceInstallPattern = regexp.MustCompile(
	`\bsystemctl\s+(enable|daemon-reload)\b` +
		`|` +
		`\bcrontab\s+-[le]\b`,
)

var EncryptedC2Pattern = regexp.MustCompile(
	`\bopenssl\s+s_client\b`,
)

type PatternMatch struct {
	Pattern  *regexp.Regexp
	Severity types.Severity
	Label    string
}

var SuspiciousPatterns = []PatternMatch{
	{ReverseShellPattern, types.SeverityCritical, "reverse shell pattern"},
	{DownloadExecPattern, types.SeverityHigh, "download-and-execute chain"},
	{EncodingPattern, types.SeverityHigh, "encoded/obfuscated payload"},
	{NetworkToolPattern, types.SeverityMedium, "network tool invocation"},
	{ScriptLangPattern, types.SeverityMedium, "inline script execution"},
	{TempDirPattern, types.SeverityMedium, "temporary directory reference"},
	{AliasHijackPattern, types.SeverityHigh, "alias hijacking"},
	{LDPreloadPattern, types.SeverityCritical, "LD_PRELOAD manipulation"},
	{PathManipPattern, types.SeverityHigh, "PATH manipulation to temp dir"},
	{NohupPattern, types.SeverityMedium, "background process launch"},
	{EvalExecPattern, types.SeverityHigh, "dynamic eval/exec"},
	{SuidPattern, types.SeverityCritical, "SUID bit manipulation"},
	{AccountCreatePattern, types.SeverityHigh, "account creation/modification"},
	{ImmutablePattern, types.SeverityHigh, "file attribute manipulation"},
	{
		PersistenceInstallPattern,
		types.SeverityMedium,
		"persistence self-installation",
	},
	{EncryptedC2Pattern, types.SeverityHigh, "encrypted C2 channel"},
}

func MatchLine(
	line string,
) (matched bool, sev types.Severity, label string) {
	best := types.SeverityInfo
	for _, p := range SuspiciousPatterns {
		if p.Pattern.MatchString(line) {
			if !matched || p.Severity > best {
				best = p.Severity
				label = p.Label
			}
			matched = true
		}
	}
	return matched, best, label
}
