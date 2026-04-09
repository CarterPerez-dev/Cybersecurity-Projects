// ©AngelaMos | 2026
// registry_test.go

package parser

import (
	"testing"

	"github.com/CarterPerez-dev/bomber/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubParser struct {
	ecosystem types.Ecosystem
	detected  bool
}

func (s *stubParser) Detect(string) bool                          { return s.detected }
func (s *stubParser) Parse(string) (*types.DependencyGraph, error) { return nil, nil }
func (s *stubParser) Ecosystem() types.Ecosystem                   { return s.ecosystem }

func TestRegistryDetect(t *testing.T) {
	reg := NewRegistry()
	goParser := &stubParser{ecosystem: types.EcosystemGo, detected: true}
	nodeParser := &stubParser{ecosystem: types.EcosystemNode, detected: false}

	reg.Register(goParser)
	reg.Register(nodeParser)

	detected := reg.Detect("some/dir")
	require.Len(t, detected, 1)
	assert.Equal(t, types.EcosystemGo, detected[0].Ecosystem())
}

func TestRegistryDetectEmpty(t *testing.T) {
	reg := NewRegistry()
	detected := reg.Detect("some/dir")
	assert.Empty(t, detected)
}

func TestRegistryAll(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&stubParser{ecosystem: types.EcosystemGo})
	reg.Register(&stubParser{ecosystem: types.EcosystemNode})

	assert.Len(t, reg.All(), 2)
}
