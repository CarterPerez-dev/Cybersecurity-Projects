// ©AngelaMos | 2026
// config.go

package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	defaultDBPath = "nadezhda.db"

	defaultUserAgent            = "nadezhda/0.1 (+https://github.com/CarterPerez-dev/nadezhda)"
	defaultPerHostRate          = 0.5
	defaultPerHostBurst         = 1
	defaultTimeoutSeconds       = 25
	defaultSourceTimeoutSeconds = 90
	defaultWorkers              = 8
	defaultMaxRetries           = 3

	defaultCacheTTLHours    = 24
	defaultNegativeTTLHours = 3

	defaultTitleJaccard  = 0.6
	defaultWindowHours   = 72
	defaultLookbackHours = 168

	trackingUTMPrefix = "utm_*"

	defaultHalfLifeHours = 48
	defaultVelocityNorm  = 0.5

	defaultWeightRecency  = 0.20
	defaultWeightCVSS     = 0.15
	defaultWeightKEV      = 0.25
	defaultWeightEPSS     = 0.15
	defaultWeightVelocity = 0.15
	defaultWeightSource   = 0.05
	defaultWeightKeyword  = 0.05

	defaultAIProvider   = "qwen"
	defaultQwenBaseURL  = "http://localhost:11434/v1"
	defaultQwenModel    = "qwen2.5:7b"
	defaultOpenAIURL    = "https://api.openai.com/v1"
	defaultOpenAIModel  = "gpt-4o-mini"
	defaultGeminiURL    = "https://generativelanguage.googleapis.com/v1beta/openai/"
	defaultGeminiModel  = "gemini-2.5-flash"
	defaultAnthropicURL = "https://api.anthropic.com/v1"
	defaultClaudeModel  = "claude-opus-4-8"
)

var defaultTrackingParams = []string{
	trackingUTMPrefix, "gclid", "fbclid", "ref", "mc_cid", "mc_eid",
}

type Fetch struct {
	UserAgent            string  `yaml:"user_agent"`
	PerHostRate          float64 `yaml:"per_host_rate"`
	PerHostBurst         int     `yaml:"per_host_burst"`
	TimeoutSeconds       int     `yaml:"timeout_seconds"`
	SourceTimeoutSeconds int     `yaml:"source_timeout_seconds"`
	Workers              int     `yaml:"workers"`
	MaxRetries           int     `yaml:"max_retries"`
}

type Enrich struct {
	CacheTTLHours    int    `yaml:"cache_ttl_hours"`
	NegativeTTLHours int    `yaml:"negative_ttl_hours"`
	NVDAPIKey        string `yaml:"nvd_api_key"`
}

type Cluster struct {
	TitleJaccard   float64  `yaml:"title_jaccard_threshold"`
	WindowHours    int      `yaml:"window_hours"`
	LookbackHours  int      `yaml:"lookback_hours"`
	TrackingParams []string `yaml:"tracking_params"`
}

type Weights struct {
	Recency  float64 `yaml:"recency"`
	CVSS     float64 `yaml:"cvss"`
	KEV      float64 `yaml:"kev"`
	EPSS     float64 `yaml:"epss"`
	Velocity float64 `yaml:"velocity"`
	Source   float64 `yaml:"source"`
	Keyword  float64 `yaml:"keyword"`
}

type Rank struct {
	HalfLifeHours int     `yaml:"half_life_hours"`
	VelocityNorm  float64 `yaml:"velocity_norm"`
	Weights       Weights `yaml:"weights"`
}

type Provider struct {
	BaseURL string `yaml:"base_url"`
	Model   string `yaml:"model"`
}

type AI struct {
	Enabled   bool     `yaml:"enabled"`
	Provider  string   `yaml:"provider"`
	Qwen      Provider `yaml:"qwen"`
	OpenAI    Provider `yaml:"openai"`
	Gemini    Provider `yaml:"gemini"`
	Anthropic Provider `yaml:"anthropic"`
}

type Config struct {
	DBPath      string   `yaml:"db_path"`
	SourcesPath string   `yaml:"sources_path"`
	Watchlist   []string `yaml:"watchlist"`
	Fetch       Fetch    `yaml:"fetch"`
	Enrich      Enrich   `yaml:"enrich"`
	Cluster     Cluster  `yaml:"cluster"`
	Rank        Rank     `yaml:"rank"`
	AI          AI       `yaml:"ai"`
}

func Default() Config {
	return Config{
		DBPath: defaultDBPath,
		Fetch: Fetch{
			UserAgent:            defaultUserAgent,
			PerHostRate:          defaultPerHostRate,
			PerHostBurst:         defaultPerHostBurst,
			TimeoutSeconds:       defaultTimeoutSeconds,
			SourceTimeoutSeconds: defaultSourceTimeoutSeconds,
			Workers:              defaultWorkers,
			MaxRetries:           defaultMaxRetries,
		},
		Enrich: Enrich{
			CacheTTLHours:    defaultCacheTTLHours,
			NegativeTTLHours: defaultNegativeTTLHours,
		},
		Cluster: Cluster{
			TitleJaccard:   defaultTitleJaccard,
			WindowHours:    defaultWindowHours,
			LookbackHours:  defaultLookbackHours,
			TrackingParams: defaultTrackingParams,
		},
		Rank: Rank{
			HalfLifeHours: defaultHalfLifeHours,
			VelocityNorm:  defaultVelocityNorm,
			Weights: Weights{
				Recency:  defaultWeightRecency,
				CVSS:     defaultWeightCVSS,
				KEV:      defaultWeightKEV,
				EPSS:     defaultWeightEPSS,
				Velocity: defaultWeightVelocity,
				Source:   defaultWeightSource,
				Keyword:  defaultWeightKeyword,
			},
		},
		AI: AI{
			Enabled:   false,
			Provider:  defaultAIProvider,
			Qwen:      Provider{BaseURL: defaultQwenBaseURL, Model: defaultQwenModel},
			OpenAI:    Provider{BaseURL: defaultOpenAIURL, Model: defaultOpenAIModel},
			Gemini:    Provider{BaseURL: defaultGeminiURL, Model: defaultGeminiModel},
			Anthropic: Provider{BaseURL: defaultAnthropicURL, Model: defaultClaudeModel},
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	if c.DBPath == "" {
		return fmt.Errorf("config: db_path must not be empty")
	}
	if c.Fetch.Workers < 1 {
		return fmt.Errorf("config: fetch.workers must be >= 1, got %d", c.Fetch.Workers)
	}
	if c.Fetch.PerHostRate <= 0 {
		return fmt.Errorf("config: fetch.per_host_rate must be > 0, got %v", c.Fetch.PerHostRate)
	}
	if c.Fetch.PerHostBurst < 1 {
		return fmt.Errorf("config: fetch.per_host_burst must be >= 1, got %d", c.Fetch.PerHostBurst)
	}
	if c.Fetch.TimeoutSeconds < 1 {
		return fmt.Errorf("config: fetch.timeout_seconds must be >= 1, got %d", c.Fetch.TimeoutSeconds)
	}
	if c.Fetch.SourceTimeoutSeconds < 1 {
		return fmt.Errorf("config: fetch.source_timeout_seconds must be >= 1, got %d", c.Fetch.SourceTimeoutSeconds)
	}
	if c.Enrich.CacheTTLHours < 0 || c.Enrich.NegativeTTLHours < 0 {
		return fmt.Errorf("config: enrich TTLs must be >= 0, got cache=%d negative=%d", c.Enrich.CacheTTLHours, c.Enrich.NegativeTTLHours)
	}
	if c.Cluster.TitleJaccard < 0 || c.Cluster.TitleJaccard > 1 {
		return fmt.Errorf("config: cluster.title_jaccard_threshold must be in [0,1], got %v", c.Cluster.TitleJaccard)
	}
	if c.Cluster.WindowHours < 1 {
		return fmt.Errorf("config: cluster.window_hours must be >= 1, got %d", c.Cluster.WindowHours)
	}
	if c.Cluster.LookbackHours < 1 {
		return fmt.Errorf("config: cluster.lookback_hours must be >= 1, got %d", c.Cluster.LookbackHours)
	}
	if c.Cluster.LookbackHours < c.Cluster.WindowHours {
		return fmt.Errorf("config: cluster.lookback_hours (%d) must be >= cluster.window_hours (%d) or window edges near the corpus boundary are silently dropped", c.Cluster.LookbackHours, c.Cluster.WindowHours)
	}
	if c.Rank.HalfLifeHours < 1 {
		return fmt.Errorf("config: rank.half_life_hours must be >= 1, got %d", c.Rank.HalfLifeHours)
	}
	if c.Rank.VelocityNorm <= 0 {
		return fmt.Errorf("config: rank.velocity_norm must be > 0, got %v", c.Rank.VelocityNorm)
	}
	switch c.AI.Provider {
	case "qwen", "openai", "gemini", "anthropic":
	default:
		return fmt.Errorf("config: ai.provider must be one of qwen|openai|gemini|anthropic, got %q", c.AI.Provider)
	}
	return nil
}
