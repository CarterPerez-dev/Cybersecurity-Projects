// ©AngelaMos | 2026
// read.go

package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func Read(path string) (Record, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = root.Close() }()
	body, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return Record{}, err
	}
	var rec Record
	if err := json.Unmarshal(body, &rec); err != nil {
		return rec, err
	}
	if rec.Schema < 1 || rec.Schema > Version {
		return rec, fmt.Errorf("unsupported record schema %d", rec.Schema)
	}
	if rec.Events == nil {
		return rec, nil
	}
	events, err := root.ReadFile(rec.Events.File)
	if err != nil {
		return rec, err
	}
	sum := sha256.Sum256(events)
	if hex.EncodeToString(sum[:]) != rec.Events.SHA256 {
		return rec, errors.New("events hash does not match the run record")
	}
	return rec, nil
}
