// ©AngelaMos | 2026
// directory.go

package source

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/CarterPerez-dev/portia/pkg/types"
)

const defaultMaxFileSize = 1 << 20

type Directory struct {
	Path     string
	MaxSize  int64
	Excludes []string
}

func NewDirectory(
	path string, maxSize int64, excludes []string,
) *Directory {
	if maxSize <= 0 {
		maxSize = defaultMaxFileSize
	}
	return &Directory{
		Path:     path,
		MaxSize:  maxSize,
		Excludes: excludes,
	}
}

func (d *Directory) String() string {
	return "directory:" + d.Path
}

func (d *Directory) Chunks(
	ctx context.Context, out chan<- types.Chunk,
) error {
	return filepath.WalkDir(
		d.Path,
		func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr
			}

			if ctx.Err() != nil {
				return ctx.Err()
			}

			if entry.IsDir() {
				base := entry.Name()
				if base == ".git" || base == "node_modules" ||
					base == "vendor" || base == "__pycache__" ||
					base == ".venv" || base == "venv" ||
					base == ".svn" || base == ".hg" ||
					base == ".tox" || base == ".mypy_cache" ||
					base == ".pytest_cache" || base == ".ruff_cache" ||
					base == ".next" || base == ".nuxt" ||
					base == ".terraform" || base == ".gradle" ||
					base == "Pods" || base == "coverage" ||
					base == ".nyc_output" || base == ".bundle" ||
					base == "target" || base == ".eggs" {
					return filepath.SkipDir
				}
				return nil
			}

			rel, relErr := filepath.Rel(d.Path, path)
			if relErr != nil {
				rel = path
			}

			if d.isExcluded(rel) {
				return nil
			}

			if isBinaryExt(path) {
				return nil
			}

			info, infoErr := entry.Info()
			if infoErr != nil || info.Size() > d.MaxSize {
				return nil //nolint:nilerr
			}

			return d.emitChunks(ctx, path, rel, out)
		},
	)
}

func (d *Directory) emitChunks(
	ctx context.Context,
	absPath, relPath string,
	out chan<- types.Chunk,
) error {
	f, err := os.Open(absPath) //nolint:gosec
	if err != nil {
		return nil //nolint:nilerr
	}
	defer f.Close() //nolint:errcheck

	var buf strings.Builder
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 512*1024), 512*1024)

	lineNum := 0
	chunkStart := 1
	linesInChunk := 0

	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		lineNum++
		linesInChunk++

		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(scanner.Text())

		if linesInChunk >= 50 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- types.Chunk{
				Content:   buf.String(),
				FilePath:  relPath,
				LineStart: chunkStart,
			}:
			}
			buf.Reset()
			chunkStart = lineNum + 1
			linesInChunk = 0
		}
	}

	if buf.Len() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- types.Chunk{
			Content:   buf.String(),
			FilePath:  relPath,
			LineStart: chunkStart,
		}:
		}
	}

	return nil
}

func (d *Directory) isExcluded(relPath string) bool {
	for _, pattern := range d.Excludes {
		if matched, _ := filepath.Match( //nolint:errcheck
			pattern, filepath.Base(relPath),
		); matched {
			return true
		}
		if strings.Contains(relPath, pattern) {
			return true
		}
	}
	return false
}

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".ico": true, ".svg": true,
	".bmp": true, ".tiff": true, ".tif": true,
	".webp": true, ".avif": true, ".heic": true,
	".heif": true, ".psd": true, ".raw": true,
	".cr2":  true,
	".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".otf": true,
	".mp3": true, ".mp4": true, ".avi": true,
	".mkv": true, ".mov": true, ".wmv": true,
	".flv": true, ".webm": true, ".flac": true,
	".wav": true, ".ogg": true, ".aac": true,
	".m4a": true,
	".zip": true, ".tar": true, ".gz": true,
	".rar": true, ".7z": true, ".bz2": true,
	".xz": true, ".zst": true, ".lz4": true,
	".lzma": true, ".cab": true,
	".deb": true, ".rpm": true, ".msi": true,
	".dmg": true, ".iso": true, ".img": true,
	".snap": true,
	".pdf":  true, ".exe": true, ".dll": true,
	".so": true, ".dylib": true, ".bin": true,
	".o": true, ".a": true, ".class": true,
	".jar": true, ".war": true, ".ear": true,
	".pyc": true, ".pyo": true, ".wasm": true,
	".db": true, ".sqlite": true, ".sqlite3": true,
	".dat": true, ".npy": true, ".npz": true,
	".h5": true, ".hdf5": true, ".parquet": true,
	".tfrecord": true, ".pkl": true, ".pickle": true,
	".pt": true, ".onnx": true, ".safetensors": true,
}

func isBinaryExt(path string) bool {
	return binaryExts[strings.ToLower(filepath.Ext(path))]
}
