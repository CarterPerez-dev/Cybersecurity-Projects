// ©AngelaMos | 2026
// configuration.go

package experiment

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

type ParameterValue struct {
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
	Env   string `json:"env,omitempty"   yaml:"env,omitempty"`
}

type Configuration struct {
	Schema     int                       `json:"schema_version"        yaml:"schema_version"`
	Experiment string                    `json:"experiment"            yaml:"experiment"`
	Project    string                    `json:"project,omitempty"     yaml:"project,omitempty"`
	Parameters map[string]ParameterValue `json:"parameters"            yaml:"parameters"`
	Timing     Schedule                  `json:"timing"                yaml:"timing"`
	AbortAfter int                       `json:"abort_after,omitempty" yaml:"abort_after,omitempty"`
	Target     Identity                  `json:"target"                yaml:"target"`
	Versions   map[string]string         `json:"versions,omitempty"    yaml:"versions,omitempty"`
}

type Identity struct {
	ID      string `json:"id,omitempty"       yaml:"id,omitempty"`
	Image   string `json:"image,omitempty"    yaml:"image,omitempty"`
	ImageID string `json:"image_id,omitempty" yaml:"image_id,omitempty"`
	Daemon  string `json:"daemon,omitempty"   yaml:"daemon,omitempty"`
}

type Schedule struct {
	Sample   string `json:"sample_every" yaml:"sample_every"`
	Baseline string `json:"baseline_for" yaml:"baseline_for"`
	Fault    string `json:"fault_for"    yaml:"fault_for"`
	Recovery string `json:"recover_for"  yaml:"recover_for"`
}

func configuration(name string, p *Params, timing Timing) Configuration {
	t := timing.withDefaults()
	config := Configuration{
		Schema: 1, Experiment: name,
		Parameters: make(map[string]ParameterValue, len(p.values)),
		Timing: Schedule{
			Sample: t.SampleInterval.String(), Baseline: t.BaselineFor.String(),
			Fault: t.FaultFor.String(), Recovery: t.RecoveryFor.String(),
		},
	}
	for name, value := range p.values {
		param := ParameterValue{Value: value}
		if sensitiveParameter(name, value) {
			param = ParameterValue{Env: "KHAOS_" + strings.ToUpper(
				strings.ReplaceAll(name, "-", "_"),
			)}
		}
		config.Parameters[name] = param
	}
	return config
}

func sensitiveParameter(name, value string) bool {
	if value == "" {
		return false
	}
	if strings.Contains(name, "token") {
		return true
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme != "" &&
		(parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "")
}

func (c Configuration) Resolve(
	lookup func(string) (string, bool),
) (map[string]string, Timing, error) {
	if c.Schema != 1 || c.AbortAfter < 0 {
		return nil, Timing{}, fmt.Errorf(
			"unsupported configuration schema %d or negative abort_after",
			c.Schema,
		)
	}
	params := make(map[string]string, len(c.Parameters))
	for name, source := range c.Parameters {
		value := source.Value
		if source.Env != "" {
			if value != "" {
				return nil, Timing{}, fmt.Errorf(
					"parameter %s must choose value or env", name,
				)
			}
			var found bool
			value, found = lookup(source.Env)
			if !found {
				return nil, Timing{}, fmt.Errorf(
					"parameter %s needs environment variable %s",
					name, source.Env,
				)
			}
		}
		params[name] = value
	}
	timing, err := c.Timing.Resolve()
	return params, timing, err
}

func (s Schedule) Resolve() (Timing, error) {
	timing := Timing{}
	for _, field := range []struct {
		name string
		raw  string
		into *time.Duration
	}{
		{"sample_every", s.Sample, &timing.SampleInterval},
		{"baseline_for", s.Baseline, &timing.BaselineFor},
		{"fault_for", s.Fault, &timing.FaultFor},
		{"recover_for", s.Recovery, &timing.RecoveryFor},
	} {
		if field.raw == "" {
			continue
		}
		value, err := time.ParseDuration(field.raw)
		if err != nil || value <= 0 {
			return Timing{}, fmt.Errorf(
				"timing.%s must be a positive duration", field.name,
			)
		}
		*field.into = value
	}
	return timing.withDefaults(), nil
}
