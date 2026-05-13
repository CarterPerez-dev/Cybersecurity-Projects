// ©AngelaMos | 2026
// recipes.go

package recipes

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"sort"
)

const (
	alphaUpperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	alphaMixedAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alphaHexLower   = "0123456789abcdef"

	keyAWS    = "aws"
	keyStripe = "stripe"
	keyGitHub = "github"
	keyDB     = "db"
)

type EnvLine struct {
	Comment string
	Key     string
	Value   string
}

type Recipe interface {
	Name() string
	Generate() []EnvLine
}

var registry = map[string]Recipe{
	keyAWS:    AWS{},
	keyStripe: Stripe{},
	keyGitHub: GitHub{},
	keyDB:     DB{},
}

func Get(key string) (Recipe, bool) {
	r, ok := registry[key]
	return r, ok
}

func AvailableKeys() []string {
	keys := make([]string, 0, len(registry))
	for k := range registry {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func RandomAlnumUpper(length int) string {
	return randomString(alphaUpperAlnum, length)
}

func RandomAlnumMixed(length int) string {
	return randomString(alphaMixedAlnum, length)
}

func RandomHexLower(length int) string {
	return randomString(alphaHexLower, length)
}

func RandomBase64(byteCount int) string {
	if byteCount <= 0 {
		return ""
	}
	buf := make([]byte, byteCount)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func RandomChoice(choices []string) string {
	if len(choices) == 0 {
		return ""
	}
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(choices))))
	if err != nil {
		return choices[0]
	}
	return choices[idx.Int64()]
}

func randomString(alphabet string, length int) string {
	if length <= 0 || alphabet == "" {
		return ""
	}
	out := make([]byte, length)
	bigLen := big.NewInt(int64(len(alphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, bigLen)
		if err != nil {
			out[i] = alphabet[0]
			continue
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out)
}
