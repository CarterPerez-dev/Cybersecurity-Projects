// ©AngelaMos | 2026
// palette.go

package theme

type Color string

const (
	BrandDeep  Color = "#4805FF"
	BrandLight Color = "#946EFF"
)

const (
	TextBright Color = "#E9E6F5"
	TextNormal Color = "#C4C0D6"
	TextDim    Color = "#8B86A6"
	TextFaint  Color = "#46425F"
)

const (
	StatusOK    Color = "#946EFF"
	StatusWarn  Color = "#D98C1E"
	StatusError Color = "#CE2417"
)

const (
	StateHeld         Color = "#946EFF"
	StateDenied       Color = "#D98C1E"
	StatePermitted    Color = "#CE2417"
	StateCrashed      Color = "#CE2417"
	StateUndetermined Color = "#5A63A8"
)

const Frame Color = "#39346B"
