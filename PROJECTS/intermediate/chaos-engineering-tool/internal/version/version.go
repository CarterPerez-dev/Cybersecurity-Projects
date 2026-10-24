// ©AngelaMos | 2026
// version.go

package version

import "runtime/debug"

const (
	Name    = "khaos"
	Tagline = "security chaos engineering"
	Author  = "carterperez.dev"
)

const (
	fallback    = "dev"
	develMarker = "(devel)"
	keyRevision = "vcs.revision"
	keyModified = "vcs.modified"
	shortSHALen = 12
	devPrefix   = "dev+"
	dirtySuffix = "+dirty"
	trueValue   = "true"
)

var ldflagsVersion string

func Version() string {
	if ldflagsVersion != "" {
		return ldflagsVersion
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fallback
	}

	if v := info.Main.Version; v != "" && v != develMarker {
		return v
	}

	return fromVCS(info)
}

func fromVCS(info *debug.BuildInfo) string {
	var (
		revision string
		dirty    bool
	)

	for _, setting := range info.Settings {
		switch setting.Key {
		case keyRevision:
			revision = setting.Value
		case keyModified:
			dirty = setting.Value == trueValue
		}
	}

	if revision == "" {
		return fallback
	}

	if len(revision) > shortSHALen {
		revision = revision[:shortSHALen]
	}

	out := devPrefix + revision
	if dirty {
		out += dirtySuffix
	}

	return out
}
