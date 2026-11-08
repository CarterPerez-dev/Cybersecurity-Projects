// ©AngelaMos | 2026
// main.go

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
)

const (
	placeholderRoot   = "HONEY_TRACK_URL_PADDED_TO_FIXED_WIDTH"
	placeholderLength = 76

	pdfHeader = "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"

	objCatalog = "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
	objPages   = "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"

	pageDictFmt = "3 0 obj\n" +
		"<<\n" +
		"/Type /Page\n" +
		"/Parent 2 0 R\n" +
		"/MediaBox [0 0 612 792]\n" +
		"/Resources << >>\n" +
		"/AA << /O << /Type /Action /S /URI /URI (%s) >> >>\n" +
		">>\nendobj\n"

	xrefHeader     = "xref\n0 4\n"
	xrefFreeRecord = "0000000000 65535 f \n"
	xrefRecordFmt  = "%010d 00000 n \n"

	trailerFmt = "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"

	dirPerm  os.FileMode = 0o755
	filePerm os.FileMode = 0o644
)

func placeholder() string {
	return placeholderRoot +
		strings.Repeat("_", placeholderLength-len(placeholderRoot))
}

func main() {
	out := flag.String("out", "", "output path for template.pdf")
	flag.Parse()

	if *out == "" {
		log.Fatal("usage: buildpdftemplate -out <path>")
	}

	if err := buildTemplate(*out); err != nil {
		log.Fatalf("build pdf template: %v", err)
	}

	fmt.Printf("wrote %s\n", *out)
}

func buildTemplate(out string) (err error) {
	cleaned := filepath.Clean(out)
	if mkErr := os.MkdirAll(filepath.Dir(cleaned), dirPerm); mkErr != nil {
		return fmt.Errorf("mkdir parent: %w", mkErr)
	}

	pdfBytes := assemblePDF()

	if vErr := api.Validate(
		context.Background(),
		bytes.NewReader(pdfBytes),
		nil,
		nil,
	); vErr != nil {
		return fmt.Errorf("pdfcpu validate: %w", vErr)
	}

	full := placeholder()
	if c := bytes.Count(pdfBytes, []byte(full)); c != 1 {
		return fmt.Errorf(
			"full placeholder appears %d times, expected exactly 1",
			c,
		)
	}
	if c := bytes.Count(pdfBytes, []byte(placeholderRoot)); c != 1 {
		return fmt.Errorf(
			"placeholder root appears %d times, expected exactly 1",
			c,
		)
	}
	if len(full) != placeholderLength {
		return fmt.Errorf(
			"placeholder length is %d, expected %d",
			len(full),
			placeholderLength,
		)
	}

	f, oErr := os.OpenFile(
		cleaned,
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
		filePerm,
	)
	if oErr != nil {
		return fmt.Errorf("open output: %w", oErr)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close output: %w", cerr)
		}
	}()

	if _, wErr := f.Write(pdfBytes); wErr != nil {
		return fmt.Errorf("write pdf: %w", wErr)
	}

	sum := sha256.Sum256(pdfBytes)
	fmt.Printf("sha256: %x\n", sum)
	fmt.Printf("size:   %d bytes\n", len(pdfBytes))
	return nil
}

func assemblePDF() []byte {
	pageObj := fmt.Sprintf(pageDictFmt, placeholder())

	var buf bytes.Buffer
	buf.WriteString(pdfHeader)

	offsets := make([]int, 4)

	offsets[1] = buf.Len()
	buf.WriteString(objCatalog)

	offsets[2] = buf.Len()
	buf.WriteString(objPages)

	offsets[3] = buf.Len()
	buf.WriteString(pageObj)

	xrefOffset := buf.Len()
	buf.WriteString(xrefHeader)
	buf.WriteString(xrefFreeRecord)
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&buf, xrefRecordFmt, offsets[i])
	}

	fmt.Fprintf(&buf, trailerFmt, xrefOffset)

	return buf.Bytes()
}
