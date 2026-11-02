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

const (
	defaultAccessTokenTTL     = "15m"
	defaultRansomwareInterval = "15m"
	defaultGDELTInterval      = "15m"
)

type Config struct {
	App           AppConfig           `koanf:"app"`
	Server        ServerConfig        `koanf:"server"`
	Database      DatabaseConfig      `koanf:"database"`
	Redis         RedisConfig         `koanf:"redis"`
	JWT           JWTConfig           `koanf:"jwt"`
	RateLimit     RateLimitConfig     `koanf:"rate_limit"`
	CORS          CORSConfig          `koanf:"cors"`
	Log           LogConfig           `koanf:"log"`
	Otel          OtelConfig          `koanf:"otel"`
	Collectors    CollectorsConfig    `koanf:"collectors"`
	Notifications NotificationsConfig `koanf:"notifications"`
}

type CollectorsConfig struct {
	DShield    SourceConfig    `koanf:"dshield"`
	CFRadar    CFRadarConfig   `koanf:"cfradar"`
	CVE        CVEConfig       `koanf:"cve"`
	KEV        SourceConfig    `koanf:"kev"`
	Ransomware SourceConfig    `koanf:"ransomware"`
	GreyNoise  GreyNoiseConfig `koanf:"greynoise"`
	AbuseIPDB  AbuseIPDBConfig `koanf:"abuseipdb"`
	Coinbase   CoinbaseConfig  `koanf:"coinbase"`
	USGS       SourceConfig    `koanf:"usgs"`
	SWPC       SWPCConfig      `koanf:"swpc"`
	Wikipedia  SourceConfig    `koanf:"wikipedia"`
	GDELT      SourceConfig    `koanf:"gdelt"`
	ISS        ISSConfig       `koanf:"iss"`
}

type SourceConfig struct {
	Enabled  bool          `koanf:"enabled"`
	Interval time.Duration `koanf:"interval"`
}

type CFRadarConfig struct {
	Enabled       bool          `koanf:"enabled"`
	Interval      time.Duration `koanf:"interval"`
	BearerToken   string        `koanf:"bearer_token"`
	MinConfidence int           `koanf:"min_confidence"`
}

type CVEConfig struct {
	Enabled   bool          `koanf:"enabled"`
	Interval  time.Duration `koanf:"interval"`
	Window    time.Duration `koanf:"window"`
	NVDAPIKey string        `koanf:"nvd_api_key"`
}

type GreyNoiseConfig struct {
	Enabled bool   `koanf:"enabled"`
	APIKey  string `koanf:"api_key"`
}

type AbuseIPDBConfig struct {
	Enabled bool   `koanf:"enabled"`
	APIKey  string `koanf:"api_key"`
}

type CoinbaseConfig struct {
	Enabled    bool          `koanf:"enabled"`
	URL        string        `koanf:"url"`
	ProductIDs []string      `koanf:"product_ids"`
	Throttle   time.Duration `koanf:"throttle"`
}

type SWPCConfig struct {
	Enabled      bool          `koanf:"enabled"`
	FastInterval time.Duration `koanf:"fast_interval"`
	SlowInterval time.Duration `koanf:"slow_interval"`
}

type ISSConfig struct {
	Enabled          bool          `koanf:"enabled"`
	PositionInterval time.Duration `koanf:"position_interval"`
	TLEInterval      time.Duration `koanf:"tle_interval"`
}

type AppConfig struct {
	Name        string `koanf:"name"`
	Version     string `koanf:"version"`
	Environment string `koanf:"environment"`
	PublicURL   string `koanf:"public_url"`
	AdminEmail  string `koanf:"admin_email"`
}

type NotificationsConfig struct {
	EncryptionKey string `koanf:"encryption_key"`
}

type ServerConfig struct {
	Host             string        `koanf:"host"`
	Port             int           `koanf:"port"`
	ReadTimeout      time.Duration `koanf:"read_timeout"`
	WriteTimeout     time.Duration `koanf:"write_timeout"`
	IdleTimeout      time.Duration `koanf:"idle_timeout"`
	ShutdownTimeout  time.Duration `koanf:"shutdown_timeout"`
	TrustedProxyHops int           `koanf:"trusted_proxy_hops"`
	WSMaxConnsPerIP  int           `koanf:"ws_max_conns_per_ip"`
	WSMaxSubscribers int           `koanf:"ws_max_subscribers"`
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

type JWTConfig struct {
	PrivateKeyPath     string        `koanf:"private_key_path"`
	PublicKeyPath      string        `koanf:"public_key_path"`
	AccessTokenExpire  time.Duration `koanf:"access_token_expire"`
	RefreshTokenExpire time.Duration `koanf:"refresh_token_expire"`
	Issuer             string        `koanf:"issuer"`
	Audience           string        `koanf:"audience"`
}

type RateLimitConfig struct {
	Requests int           `koanf:"requests"`
	Window   time.Duration `koanf:"window"`
	Burst    int           `koanf:"burst"`
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
		"app.name":        "Go Backend",
		"app.version":     "1.0.0",
		"app.environment": "development",

		"server.host":                "0.0.0.0",
		"server.port":                8080,
		"server.read_timeout":        "30s",
		"server.write_timeout":       "30s",
		"server.idle_timeout":        "120s",
		"server.shutdown_timeout":    "15s",
		"server.trusted_proxy_hops":  0,
		"server.ws_max_conns_per_ip": 25,
		"server.ws_max_subscribers":  5000,

		"database.max_open_conns":     25,
		"database.max_idle_conns":     5,
		"database.conn_max_lifetime":  "1h",
		"database.conn_max_idle_time": "30m",

		"redis.pool_size":      10,
		"redis.min_idle_conns": 5,

		"jwt.access_token_expire":  defaultAccessTokenTTL,
		"jwt.refresh_token_expire": "168h",
		"jwt.issuer":               "go-backend",
		"jwt.audience":             "go-backend-api",
		"jwt.private_key_path":     "keys/private.pem",
		"jwt.public_key_path":      "keys/public.pem",

		"rate_limit.requests": 100,
		"rate_limit.window":   "1m",
		"rate_limit.burst":    20,

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
		"otel.service_name": "go-backend",

		"collectors.dshield.enabled":        true,
		"collectors.dshield.interval":       "1h",
		"collectors.cfradar.enabled":        true,
		"collectors.cfradar.interval":       "5m",
		"collectors.cfradar.min_confidence": 7,
		"collectors.cve.enabled":            true,
		"collectors.cve.interval":           "5m",
		"collectors.cve.window":             "6m",
		"collectors.kev.enabled":            true,
		"collectors.kev.interval":           "1h",
		"collectors.ransomware.enabled":     true,
		"collectors.ransomware.interval":    defaultRansomwareInterval,
		"collectors.greynoise.enabled":      true,
		"collectors.abuseipdb.enabled":      true,
		"collectors.coinbase.enabled":       true,
		"collectors.coinbase.url":           "wss://advanced-trade-ws.coinbase.com",
		"collectors.coinbase.product_ids":   []string{"BTC-USD", "ETH-USD"},
		"collectors.coinbase.throttle":      "250ms",
		"collectors.usgs.enabled":           true,
		"collectors.usgs.interval":          "1m",
		"collectors.swpc.enabled":           true,
		"collectors.swpc.fast_interval":     "1m",
		"collectors.swpc.slow_interval":     "3h",
		"collectors.wikipedia.enabled":      true,
		"collectors.wikipedia.interval":     "5m",
		"collectors.gdelt.enabled":          true,
		"collectors.gdelt.interval":         defaultGDELTInterval,
		"collectors.iss.enabled":            true,
		"collectors.iss.position_interval":  "10s",
		"collectors.iss.tle_interval":       "24h",
	}

	for key, value := range defaults {
		if err := k.Set(key, value); err != nil {
			return fmt.Errorf("set default %s: %w", key, err)
		}
	}

	return nil
}

var envKeyMap = map[string]string{
	"DATABASE_URL":                "database.url",
	"REDIS_URL":                   "redis.url",
	"ENVIRONMENT":                 "app.environment",
	"HOST":                        "server.host",
	"PORT":                        "server.port",
	"TRUSTED_PROXY_HOPS":          "server.trusted_proxy_hops",
	"WS_MAX_CONNS_PER_IP":         "server.ws_max_conns_per_ip",
	"WS_MAX_SUBSCRIBERS":          "server.ws_max_subscribers",
	"LOG_LEVEL":                   "log.level",
	"LOG_FORMAT":                  "log.format",
	"JWT_PRIVATE_KEY_PATH":        "jwt.private_key_path",
	"JWT_PUBLIC_KEY_PATH":         "jwt.public_key_path",
	"JWT_ACCESS_TOKEN_EXPIRE":     "jwt.access_token_expire",
	"JWT_REFRESH_TOKEN_EXPIRE":    "jwt.refresh_token_expire",
	"JWT_ISSUER":                  "jwt.issuer",
	"JWT_AUDIENCE":                "jwt.audience",
	"RATE_LIMIT_REQUESTS":         "rate_limit.requests",
	"RATE_LIMIT_WINDOW":           "rate_limit.window",
	"RATE_LIMIT_BURST":            "rate_limit.burst",
	"OTEL_ENDPOINT":               "otel.endpoint",
	"OTEL_EXPORTER_OTLP_ENDPOINT": "otel.endpoint",
	"OTEL_SERVICE_NAME":           "otel.service_name",
	"OTEL_ENABLED":                "otel.enabled",
	"OTEL_INSECURE":               "otel.insecure",
	"OTEL_SAMPLE_RATE":            "otel.sample_rate",
	"NVD_API_KEY":                 "collectors.cve.nvd_api_key",
	"CF_RADAR_TOKEN":              "collectors.cfradar.bearer_token",
	"GREYNOISE_API_KEY":           "collectors.greynoise.api_key",
	"ABUSEIPDB_API_KEY":           "collectors.abuseipdb.api_key",
	"NOTIFICATION_ENCRYPTION_KEY": "notifications.encryption_key",
	"PUBLIC_URL":                  "app.public_url",
	"ADMIN_EMAIL":                 "app.admin_email",
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

	if c.JWT.PrivateKeyPath == "" {
		return fmt.Errorf("JWT_PRIVATE_KEY_PATH is required")
	}

	if c.JWT.PublicKeyPath == "" {
		return fmt.Errorf("JWT_PUBLIC_KEY_PATH is required")
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
