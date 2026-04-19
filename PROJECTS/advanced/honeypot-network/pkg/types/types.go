/*
©AngelaMos | 2026
types.go

Shared domain types for the hive honeypot network

Defines the core data structures that flow through every subsystem:
service enums, the unified event envelope, session and attacker
models, credential and IOC records, and the Service interface that
all honeypot protocols implement. Zero imports from internal packages.
*/

package types

import (
	"context"
	"encoding/json"
	"net"
	"time"
)

const Version = "0.1.0"

type ServiceType int

const (
	ServiceSSH ServiceType = iota
	ServiceHTTP
	ServiceFTP
	ServiceSMB
	ServiceMySQL
	ServiceRedis
)

var serviceNames = map[ServiceType]string{
	ServiceSSH:   "ssh",
	ServiceHTTP:  "http",
	ServiceFTP:   "ftp",
	ServiceSMB:   "smb",
	ServiceMySQL: "mysql",
	ServiceRedis: "redis",
}

var serviceLabels = map[ServiceType]string{
	ServiceSSH:   "SSH",
	ServiceHTTP:  "HTTP",
	ServiceFTP:   "FTP",
	ServiceSMB:   "SMB",
	ServiceMySQL: "MySQL",
	ServiceRedis: "Redis",
}

func (s ServiceType) String() string {
	return serviceNames[s]
}

func (s ServiceType) Label() string {
	return serviceLabels[s]
}

func (s ServiceType) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func ParseServiceType(s string) (ServiceType, bool) {
	for st, name := range serviceNames {
		if name == s {
			return st, true
		}
	}
	return ServiceSSH, false
}

type EventType int

const (
	EventConnect EventType = iota
	EventDisconnect
	EventLoginSuccess
	EventLoginFailed
	EventCommand
	EventCommandOutput
	EventFileUpload
	EventFileDownload
	EventRequest
	EventExploit
	EventScan
)

var eventNames = map[EventType]string{
	EventConnect:       "connect",
	EventDisconnect:    "disconnect",
	EventLoginSuccess:  "login.success",
	EventLoginFailed:   "login.failed",
	EventCommand:       "command.input",
	EventCommandOutput: "command.output",
	EventFileUpload:    "file.upload",
	EventFileDownload:  "file.download",
	EventRequest:       "request",
	EventExploit:       "exploit.attempt",
	EventScan:          "scan.detected",
}

func (e EventType) String() string {
	return eventNames[e]
}

func (e EventType) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

func ParseEventType(s string) (EventType, bool) {
	for et, name := range eventNames {
		if name == s {
			return et, true
		}
	}
	return EventConnect, false
}

type Protocol int

const (
	ProtocolTCP Protocol = iota
	ProtocolUDP
)

var protocolNames = map[Protocol]string{
	ProtocolTCP: "tcp",
	ProtocolUDP: "udp",
}

func (p Protocol) String() string {
	return protocolNames[p]
}

func (p Protocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

type GeoInfo struct {
	CountryCode string  `json:"country_code"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         int     `json:"asn"`
	Org         string  `json:"org"`
}

type Event struct {
	ID            string          `json:"id"`
	SessionID     string          `json:"session_id"`
	SensorID      string          `json:"sensor_id"`
	Timestamp     time.Time       `json:"timestamp"`
	ReceivedAt    time.Time       `json:"received_at"`
	ServiceType   ServiceType     `json:"service_type"`
	EventType     EventType       `json:"event_type"`
	SourceIP      string          `json:"source_ip"`
	SourcePort    int             `json:"source_port"`
	DestPort      int             `json:"dest_port"`
	Protocol      Protocol        `json:"protocol"`
	SchemaVersion int             `json:"schema_version"`
	Geo           *GeoInfo        `json:"geo,omitempty"`
	Tags          []string        `json:"tags,omitempty"`
	ServiceData   json.RawMessage `json:"service_data,omitempty"`
}

type Session struct {
	ID              string      `json:"id"`
	SensorID        string      `json:"sensor_id"`
	StartedAt       time.Time   `json:"started_at"`
	EndedAt         *time.Time  `json:"ended_at,omitempty"`
	ServiceType     ServiceType `json:"service_type"`
	SourceIP        string      `json:"source_ip"`
	SourcePort      int         `json:"source_port"`
	DestPort        int         `json:"dest_port"`
	ClientVersion   string      `json:"client_version,omitempty"`
	LoginSuccess    bool        `json:"login_success"`
	Username        string      `json:"username,omitempty"`
	CommandCount    int         `json:"command_count"`
	MITRETechniques []string    `json:"mitre_techniques,omitempty"`
	ThreatScore     int         `json:"threat_score"`
	Tags            []string    `json:"tags,omitempty"`
}

type Attacker struct {
	ID            int64     `json:"id"`
	IP            string    `json:"ip"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	TotalEvents   int64     `json:"total_events"`
	TotalSessions int       `json:"total_sessions"`
	Geo           GeoInfo   `json:"geo"`
	ThreatScore   int       `json:"threat_score"`
	ToolFamily    string    `json:"tool_family,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
}

type Credential struct {
	ID          int64       `json:"id"`
	SessionID   string      `json:"session_id"`
	Timestamp   time.Time   `json:"timestamp"`
	ServiceType ServiceType `json:"service_type"`
	SourceIP    string      `json:"source_ip"`
	Username    string      `json:"username"`
	Password    string      `json:"password"`
	PublicKey   string      `json:"public_key,omitempty"`
	AuthMethod  string      `json:"auth_method"`
	Success     bool        `json:"success"`
}

type CapturedFile struct {
	ID        int64       `json:"id"`
	SessionID string      `json:"session_id"`
	Timestamp time.Time   `json:"timestamp"`
	SourceIP  string      `json:"source_ip"`
	Service   ServiceType `json:"service"`
	Filename  string      `json:"filename"`
	Size      int64       `json:"size"`
	SHA256    string      `json:"sha256"`
	MD5       string      `json:"md5"`
	MimeType  string      `json:"mime_type"`
	Content   []byte      `json:"-"`
}

type IOCType int

const (
	IOCIPv4 IOCType = iota
	IOCIPv6
	IOCDomain
	IOCURL
	IOCHashSHA256
	IOCHashMD5
	IOCSSHKey
	IOCUserAgent
	IOCEmail
)

var iocTypeNames = map[IOCType]string{
	IOCIPv4:       "ipv4",
	IOCIPv6:       "ipv6",
	IOCDomain:     "domain",
	IOCURL:        "url",
	IOCHashSHA256: "sha256",
	IOCHashMD5:    "md5",
	IOCSSHKey:     "ssh-key",
	IOCUserAgent:  "user-agent",
	IOCEmail:      "email",
}

func (t IOCType) String() string {
	return iocTypeNames[t]
}

func (t IOCType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func ParseIOCType(s string) (IOCType, bool) {
	for t, name := range iocTypeNames {
		if name == s {
			return t, true
		}
	}
	return IOCIPv4, false
}

type IOC struct {
	ID         int64     `json:"id"`
	Type       IOCType   `json:"type"`
	Value      string    `json:"value"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	SightCount int       `json:"sight_count"`
	Confidence int       `json:"confidence"`
	Source     string    `json:"source"`
	Tags       []string  `json:"tags,omitempty"`
}

type MITREDetection struct {
	ID          int64       `json:"id"`
	SessionID   string      `json:"session_id"`
	TechniqueID string      `json:"technique_id"`
	Tactic      string      `json:"tactic"`
	Confidence  int         `json:"confidence"`
	SourceIP    string      `json:"source_ip"`
	ServiceType ServiceType `json:"service_type"`
	Evidence    string      `json:"evidence"`
	DetectedAt  time.Time   `json:"detected_at"`
}

type Sensor struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	Region    string    `json:"region"`
	PublicIP  string    `json:"public_ip"`
	Services  []string  `json:"services"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"`
}

type Service interface {
	Name() string
	Start(ctx context.Context) error
}

func RemoteAddr(conn net.Conn) (string, int) {
	addr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return "", 0
	}
	return addr.IP.String(), addr.Port
}
