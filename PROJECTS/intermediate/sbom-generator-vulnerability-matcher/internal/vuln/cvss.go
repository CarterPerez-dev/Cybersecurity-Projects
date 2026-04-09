// ©AngelaMos | 2026
// cvss.go

package vuln

import (
	"math"
	"strings"
)

const (
	scopeUnchanged = 0.0
	scopeChanged   = 1.0
)

type cvssMetrics struct {
	AV float64
	AC float64
	PR float64
	UI float64
	S  float64
	C  float64
	I  float64
	A  float64
}

var avWeights = map[string]float64{
	"N": 0.85,
	"A": 0.62,
	"L": 0.55,
	"P": 0.20,
}

var acWeights = map[string]float64{
	"L": 0.77,
	"H": 0.44,
}

var prWeightsUnchanged = map[string]float64{
	"N": 0.85,
	"L": 0.62,
	"H": 0.27,
}

var prWeightsChanged = map[string]float64{
	"N": 0.85,
	"L": 0.68,
	"H": 0.50,
}

var uiWeights = map[string]float64{
	"N": 0.85,
	"R": 0.62,
}

var ciaWeights = map[string]float64{
	"H": 0.56,
	"L": 0.22,
	"N": 0.0,
}

func parseCVSSVector(vector string) *cvssMetrics {
	if !strings.HasPrefix(vector, "CVSS:3") {
		return nil
	}

	parts := strings.Split(vector, "/")
	if len(parts) < 9 {
		return nil
	}

	vals := make(map[string]string, 8)
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			vals[kv[0]] = kv[1]
		}
	}

	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, key := range required {
		if _, ok := vals[key]; !ok {
			return nil
		}
	}

	av, ok := avWeights[vals["AV"]]
	if !ok {
		return nil
	}
	ac, ok := acWeights[vals["AC"]]
	if !ok {
		return nil
	}
	ui, ok := uiWeights[vals["UI"]]
	if !ok {
		return nil
	}
	c, ok := ciaWeights[vals["C"]]
	if !ok {
		return nil
	}
	i, ok := ciaWeights[vals["I"]]
	if !ok {
		return nil
	}
	a, ok := ciaWeights[vals["A"]]
	if !ok {
		return nil
	}

	var s float64
	switch vals["S"] {
	case "U":
		s = scopeUnchanged
	case "C":
		s = scopeChanged
	default:
		return nil
	}

	prMap := prWeightsUnchanged
	if s == scopeChanged {
		prMap = prWeightsChanged
	}
	pr, ok := prMap[vals["PR"]]
	if !ok {
		return nil
	}

	return &cvssMetrics{
		AV: av,
		AC: ac,
		PR: pr,
		UI: ui,
		S:  s,
		C:  c,
		I:  i,
		A:  a,
	}
}

func parseCVSSScore(vector string) float64 {
	metrics := parseCVSSVector(vector)
	if metrics == nil {
		return 0
	}

	iss := 1 - ((1 - metrics.C) * (1 - metrics.I) * (1 - metrics.A))

	var impact float64
	if metrics.S == scopeUnchanged {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0
	}

	exploitability := 8.22 * metrics.AV * metrics.AC * metrics.PR * metrics.UI

	var score float64
	if metrics.S == scopeUnchanged {
		score = math.Min(impact+exploitability, 10)
	} else {
		score = math.Min(1.08*(impact+exploitability), 10)
	}

	return cvssRoundUp(score)
}

func cvssRoundUp(val float64) float64 {
	shifted := math.Round(val*100000) / 100000
	return math.Ceil(shifted*10) / 10
}
