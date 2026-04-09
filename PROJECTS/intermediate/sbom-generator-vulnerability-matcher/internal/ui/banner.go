// ©AngelaMos | 2026
// banner.go

package ui

import "fmt"

func PrintBanner() {
	fmt.Printf("\n  %s %s\n\n", Bold("bomber"), Dim("SBOM generator & vulnerability matcher"))
}

func PrintBannerWithArt() {
	fmt.Println()
	fmt.Printf("  %s\n", Red(" ██▄ ▄▀▄ █▄ ▄█ ██▄ ██▀ █▀▄"))
	fmt.Printf("  %s\n", Cyan(" █▄█ ▀▄▀ █ ▀ █ █▄█ █▄▄ █▀▄"))
	fmt.Println()
	fmt.Printf("  %s\n\n", Dim("SBOM generator & vulnerability matcher"))
}
