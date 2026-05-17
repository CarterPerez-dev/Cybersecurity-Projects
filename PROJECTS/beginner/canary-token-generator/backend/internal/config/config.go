// ©AngelaMos | 2026
// config.go

package config

import (
	"fmt"
	"sync"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const defaultCanaryBaseURL = "http://localhost:8080"

type Config struct {
	App       AppConfig       `koanf:"app"`
	Server    ServerConfig    `koanf:"server"`
	Database  DatabaseConfig  `koanf:"database"`
	Redis     RedisConfig     `koanf:"redis"`
	RateLimit RateLimitConfig `koanf:"rate_limit"`
	CORS      CORSConfig      `koanf:"cors"`
	Log       LogConfig       `koanf:"log"`
	Otel      OtelConfig      `koanf:"otel"`
	Canary    CanaryConfig    `koanf:"canary"`
	Turnstile TurnstileConfig `koanf:"turnstile"`
	MySQL     MySQLConfig     `koanf:"mysql"`
	Notify    NotifyConfig    `koanf:"notify"`
	Operator  OperatorConfig  `koanf:"operator"`
	GeoIP     GeoIPConfig     `koanf:"geoip"`
}

type OperatorConfig struct {
	Token string `koanf:"token"`
}

type GeoIPConfig struct {
	Path string `koanf:"path"`
}

type NotifyConfig struct {
	DedupTTL          time.Duration `koanf:"dedup_ttl"`
	SendTimeout       time.Duration `koanf:"send_timeout"`
	MaxTries          uint          `koanf:"max_tries"`
	MaxElapsed        time.Duration `koanf:"max_elapsed"`
	InitialInterval   time.Duration `koanf:"initial_interval"`
	RetentionInterval time.Duration `koanf:"retention_interval"`
	RetentionLimit    int           `koanf:"retention_limit"`
	WebhookHMACSecret string        `koanf:"webhook_hmac_secret"`
	TelegramAPIBase   string        `koanf:"telegram_api_base"`
	FingerprintWindow time.Duration `koanf:"fingerprint_window"`
}

type CanaryConfig struct {
	BaseURL   string `koanf:"base_url"`
	ManageURL string `koanf:"manage_url"`
}

type TurnstileConfig struct {
	SecretKey string `koanf:"secret_key"`
	SiteKey   string `koanf:"site_key"`
}

type MySQLConfig struct {
	Enabled    bool   `koanf:"enabled"`
	Addr       string `koanf:"addr"`
	PublicHost string `koanf:"public_host"`
	PublicPort int    `koanf:"public_port"`
}

type AppConfig struct {
	Name        string `koanf:"name"`
	Version     string `koanf:"version"`
	Environment string `koanf:"environment"`
}

type ServerConfig struct {
	Host            string        `koanf:"host"`
	Port            int           `koanf:"port"`
	ReadTimeout     time.Duration `koanf:"read_timeout"`
	WriteTimeout    time.Duration `koanf:"write_timeout"`
	IdleTimeout     time.Duration `koanf:"idle_timeout"`
	ShutdownTimeout time.Duration `koanf:"shutdown_timeout"`
}

type DatabaseConfig struct {
	URL             string        `koanf:"url"`
	MaxOpenConns    int           `koanf:"max_open_conns"`
	MaxIdleConns    int           `koanf:"max_idle_conns"`
	ConnMaxLifetime time.Duration `koanf:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `koanf:"conn_max_idle_time"`
}

type RedisConfig struct {
	URL          string `koanf:"url"`
	PoolSize     int    `koanf:"pool_size"`
	MinIdleConns int    `koanf:"min_idle_conns"`
}

type RateLimitConfig struct {
	Requests        int           `koanf:"requests"`
	Window          time.Duration `koanf:"window"`
	Burst           int           `koanf:"burst"`
	CreateMinRate   int           `koanf:"create_min_rate"`
	CreateMinBurst  int           `koanf:"create_min_burst"`
	CreateHourRate  int           `koanf:"create_hour_rate"`
	CreateHourBurst int           `koanf:"create_hour_burst"`
}

type CORSConfig struct {
	AllowedOrigins   []string `koanf:"allowed_origins"`
	AllowedMethods   []string `koanf:"allowed_methods"`
	AllowedHeaders   []string `koanf:"allowed_headers"`
	AllowCredentials bool     `koanf:"allow_credentials"`
	MaxAge           int      `koanf:"max_age"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

type OtelConfig struct {
	Endpoint    string  `koanf:"endpoint"`
	ServiceName string  `koanf:"service_name"`
	Enabled     bool    `koanf:"enabled"`
	Insecure    bool    `koanf:"insecure"`
	SampleRate  float64 `koanf:"sample_rate"`
}

var (
	cfg  *Config
	once sync.Once
)

func Load(configPath string) (*Config, error) {
	var loadErr error

	once.Do(func() {
		k := koanf.New(".")

		if err := loadDefaults(k); err != nil {
			loadErr = fmt.Errorf("load defaults: %w", err)
			return
		}

		if configPath != "" {
			if err := k.Load(
				file.Provider(configPath),
				yaml.Parser(),
			); err != nil {
				loadErr = fmt.Errorf("load config file: %w", err)
				return
			}
		}

		if err := k.Load(
			env.Provider("", ".", envKeyReplacer),
			nil,
		); err != nil {
			loadErr = fmt.Errorf("load env vars: %w", err)
			return
		}

		cfg = &Config{}
		if err := k.Unmarshal("", cfg); err != nil {
			loadErr = fmt.Errorf("unmarshal config: %w", err)
			return
		}

		if cfg.Canary.ManageURL == "" ||
			cfg.Canary.ManageURL == defaultCanaryBaseURL {
			cfg.Canary.ManageURL = cfg.Canary.BaseURL
		}

		if err := validate(cfg); err != nil {
			loadErr = fmt.Errorf("validate config: %w", err)
			return
		}
	})

	if loadErr != nil {
		return nil, loadErr
	}

	return cfg, nil
}

func Get() *Config {
	if cfg == nil {
		panic("config not loaded: call Load() first")
	}
	return cfg
}

func loadDefaults(k *koanf.Koanf) error {
	defaults := map[string]any{
		"app.name":        "Canary Token Generator",
		"app.version":     "1.0.0",
		"app.environment": "development",

		"server.host":             "0.0.0.0",
		"server.port":             8080,
		"server.read_timeout":     "30s",
		"server.write_timeout":    "30s",
		"server.idle_timeout":     "120s",
		"server.shutdown_timeout": "15s",

		"database.max_open_conns":     25,
		"database.max_idle_conns":     5,
		"database.conn_max_lifetime":  "1h",
		"database.conn_max_idle_time": "30m",

		"redis.pool_size":      10,
		"redis.min_idle_conns": 5,

		"rate_limit.requests":          100,
		"rate_limit.window":            "1m",
		"rate_limit.burst":             20,
		"rate_limit.create_min_rate":   5,
		"rate_limit.create_min_burst":  5,
		"rate_limit.create_hour_rate":  20,
		"rate_limit.create_hour_burst": 5,

		"cors.allowed_origins": []string{"http://localhost:3000"},
		"cors.allowed_methods": []string{
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
			"OPTIONS",
		},
		"cors.allowed_headers": []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-Request-ID",
		},
		"cors.allow_credentials": true,
		"cors.max_age":           300,

		"log.level":  "info",
		"log.format": "json",

		"otel.enabled":      false,
		"otel.insecure":     true,
		"otel.sample_rate":  0.1,
		"otel.service_name": "canary-token-generator",

		"canary.base_url":   defaultCanaryBaseURL,
		"canary.manage_url": defaultCanaryBaseURL,

		"turnstile.secret_key": "",
		"turnstile.site_key":   "",

		"mysql.enabled":     false,
		"mysql.addr":        "0.0.0.0:3306",
		"mysql.public_host": "localhost",
		"mysql.public_port": 3306,

		"notify.dedup_ttl":           "15m",
		"notify.send_timeout":        "30s",
		"notify.max_tries":           3,
		"notify.max_elapsed":         "30s",
		"notify.initial_interval":    "500ms",
		"notify.retention_interval":  "1h",
		"notify.retention_limit":     100,
		"notify.webhook_hmac_secret": "",
		"notify.telegram_api_base":   "https://api.telegram.org",
		"notify.fingerprint_window":  "5m",

		"operator.token": "",

		"geoip.path": "/data/GeoLite2-City.mmdb",
	}

	for key, value := range defaults {
		if err := k.Set(key, value); err != nil {
			return fmt.Errorf("set default %s: %w", key, err)
		}
	}

	return nil
}

var envKeyMap = map[string]string{
	"DATABASE_URL":                 "database.url",
	"REDIS_URL":                    "redis.url",
	"APP_ENVIRONMENT":              "app.environment",
	"HOST":                         "server.host",
	"PORT":                         "server.port",
	"LOG_LEVEL":                    "log.level",
	"LOG_FORMAT":                   "log.format",
	"RATE_LIMIT_REQUESTS":          "rate_limit.requests",
	"RATE_LIMIT_WINDOW":            "rate_limit.window",
	"RATE_LIMIT_BURST":             "rate_limit.burst",
	"OTEL_ENDPOINT":                "otel.endpoint",
	"OTEL_EXPORTER_OTLP_ENDPOINT":  "otel.endpoint",
	"OTEL_SERVICE_NAME":            "otel.service_name",
	"OTEL_ENABLED":                 "otel.enabled",
	"OTEL_INSECURE":                "otel.insecure",
	"OTEL_SAMPLE_RATE":             "otel.sample_rate",
	"CANARY_BASE_URL":              "canary.base_url",
	"PUBLIC_BASE_URL":              "canary.base_url",
	"CANARY_MANAGE_URL":            "canary.manage_url",
	"TURNSTILE_SECRET_KEY":         "turnstile.secret_key",
	"TURNSTILE_SITE_KEY":           "turnstile.site_key",
	"MYSQL_ENABLED":                "mysql.enabled",
	"MYSQL_ADDR":                   "mysql.addr",
	"MYSQL_PUBLIC_HOST":            "mysql.public_host",
	"MYSQL_PUBLIC_PORT":            "mysql.public_port",
	"RATE_LIMIT_CREATE_MIN_RATE":   "rate_limit.create_min_rate",
	"RATE_LIMIT_CREATE_MIN_BURST":  "rate_limit.create_min_burst",
	"RATE_LIMIT_CREATE_HOUR_RATE":  "rate_limit.create_hour_rate",
	"RATE_LIMIT_CREATE_HOUR_BURST": "rate_limit.create_hour_burst",
	"NOTIFY_DEDUP_TTL":             "notify.dedup_ttl",
	"NOTIFY_SEND_TIMEOUT":          "notify.send_timeout",
	"NOTIFY_MAX_TRIES":             "notify.max_tries",
	"NOTIFY_MAX_ELAPSED":           "notify.max_elapsed",
	"NOTIFY_INITIAL_INTERVAL":      "notify.initial_interval",
	"NOTIFY_RETENTION_INTERVAL":    "notify.retention_interval",
	"NOTIFY_RETENTION_LIMIT":       "notify.retention_limit",
	"WEBHOOK_HMAC_SECRET":          "notify.webhook_hmac_secret",
	"NOTIFY_TELEGRAM_API_BASE":     "notify.telegram_api_base",
	"NOTIFY_FINGERPRINT_WINDOW":    "notify.fingerprint_window",
	"OPERATOR_TOKEN":               "operator.token",
	"GEOLITE_PATH":                 "geoip.path",
}

func envKeyReplacer(s string) string {
	if mapped, ok := envKeyMap[s]; ok {
		return mapped
	}
	return ""
}

func validate(c *Config) error {
	if c.Database.URL == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}

	if c.Redis.URL == "" {
		return fmt.Errorf("REDIS_URL is required")
	}

	if c.CORS.AllowCredentials {
		for _, origin := range c.CORS.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf(
					"CORS wildcard '*' cannot be used with AllowCredentials",
				)
			}
		}
	}

	if c.App.Environment == "production" {
		if c.Otel.Enabled && c.Otel.Insecure {
			return fmt.Errorf("OTEL_INSECURE must be false in production")
		}
	}

	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("server.read_timeout must be positive")
	}

	if c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("server.write_timeout must be positive")
	}

	return nil
}

func (c *Config) IsProduction() bool {
	return c.App.Environment == "production"
}

func (c *Config) IsDevelopment() bool {
	return c.App.Environment == "development"
}

func (s *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}
