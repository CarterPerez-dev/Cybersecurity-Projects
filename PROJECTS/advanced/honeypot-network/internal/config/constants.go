/*
©AngelaMos | 2026
constants.go

Tool metadata and default values for all honeypot services

Centralizes every magic string, port number, banner, and timeout
so that no literal values appear anywhere else in the codebase.
Service banners are chosen to match real-world versions that avoid
common honeypot fingerprinting signatures.
*/

package config

import "time"

const (
	ToolName    = "hive"
	ToolVersion = "0.1.0"
	ToolVendor  = "CarterPerez-dev"
)

const (
	DefaultSSHPort   = 2222
	DefaultHTTPPort  = 8080
	DefaultFTPPort   = 2121
	DefaultSMBPort   = 4450
	DefaultMySQLPort = 3307
	DefaultRedisPort = 6380
	DefaultAPIPort   = 8000
)

const (
	SSHBanner   = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
	HTTPServer  = "Apache/2.4.57 (Ubuntu)"
	FTPBanner   = "220 ProFTPD 1.3.8b Server ready."
	MySQLBanner = "5.7.42-0ubuntu0.18.04.1"
	RedisBanner = "7.0.11"
	SMBDialect  = "SMB 2.1"
)

const (
	DefaultHostname = "ubuntu-server"
	DefaultDomain   = "internal.local"
	DefaultMOTD     = "Welcome to Ubuntu 22.04.4 LTS"
)

const SSHMOTDTemplate = "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\r\n\r\n" +
	" * Documentation:  https://help.ubuntu.com\r\n" +
	" * Management:     https://landscape.canonical.com\r\n" +
	" * Support:        https://ubuntu.com/pro\r\n\r\n" +
	"  System information as of %s\r\n\r\n" +
	"  System load:  0.08              Processes:             142\r\n" +
	"  Usage of /:   21.3%% of 39.25GB   Users logged in:       1\r\n" +
	"  Memory usage: 28%%               IPv4 address for eth0: 10.0.2.15\r\n" +
	"  Swap usage:   0%%\r\n\r\n" +
	"Last login: %s from 10.0.2.2\r\n"

const SchemaVersion = 1

const (
	DefaultDBPoolMin     = 2
	DefaultDBPoolMax     = 10
	DefaultDBTimeout     = 30 * time.Second
	DefaultDBIdleTimeout = 5 * time.Minute
)

const (
	DefaultRedisStreamKey = "honeypot:events"
	DefaultRedisMaxLen    = 100000
	DefaultRedisTTL       = 24 * time.Hour
)

const (
	DefaultRateLimitBurst    = 10
	DefaultRateLimitInterval = time.Second
	DefaultRateLimitCleanup  = 10 * time.Minute
)

const (
	DefaultMaxUploadSize   = 1 << 20
	DefaultSessionTimeout  = 30 * time.Minute
	DefaultShutdownTimeout = 10 * time.Second
	DefaultReadTimeout     = 30 * time.Second
	DefaultWriteTimeout    = 30 * time.Second
)

const (
	DefaultEventBusBuffer   = 10000
	DefaultProcessorWorkers = 4
)

const (
	DefaultReplayDir   = "/data/replays"
	DefaultGeoIPPath   = "/usr/share/GeoIP/GeoLite2-City.mmdb"
	DefaultHostKeyPath = "data/hostkey_ed25519"
	DefaultConfigPath  = "config.yaml"
)

const (
	TopicAll        = "all"
	TopicAuth       = "auth"
	TopicCommand    = "command"
	TopicConnect    = "connect"
	TopicDisconnect = "disconnect"
	TopicScan       = "scan"
	TopicExploit    = "exploit"
	TopicFile       = "file"
)
