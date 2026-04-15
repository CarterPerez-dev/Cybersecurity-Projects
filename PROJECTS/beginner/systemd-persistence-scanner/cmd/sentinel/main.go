/*
©AngelaMos | 2026
main.go

Entry point for the sentinel CLI
*/

package main

import (
	"github.com/CarterPerez-dev/sentinel/internal/cli"
	_ "github.com/CarterPerez-dev/sentinel/internal/scanner"
)

func main() {
	cli.Execute()
}
