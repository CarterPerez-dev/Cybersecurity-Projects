/*
©AngelaMos | 2026
detector.go

Rule engine for detecting MITRE ATT&CK techniques from honeypot events

Evaluates each event against single-event pattern rules and multi-event
sliding window rules. Single-event rules match on command patterns and
event types. Multi-event rules track per-IP state to detect brute force
attacks and service scanning across configurable time windows.
*/

package mitre

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	bruteForceThreshold = 5
	bruteForceWindow    = 5 * time.Minute
	scanThreshold       = 3
	scanWindow          = 60 * time.Second
)

type ipState struct {
	authHits []time.Time
	services map[types.ServiceType]time.Time
}

type Detector struct {
	index *Index
	mu    sync.Mutex
	state map[string]*ipState
}

func NewDetector() *Detector {
	return &Detector{
		index: NewIndex(),
		state: make(map[string]*ipState),
	}
}

func (d *Detector) Index() *Index {
	return d.index
}

func (d *Detector) Detect(
	ev *types.Event,
) []*types.MITREDetection {
	ids := dedupStrings(append(
		d.detectSingleEvent(ev),
		d.detectMultiEvent(ev)...,
	))

	detectedAt := ev.Timestamp
	if detectedAt.IsZero() {
		detectedAt = time.Now().UTC()
	}

	detections := make([]*types.MITREDetection, 0, len(ids))
	for _, id := range ids {
		tactic := ""
		if t := d.index.Get(id); t != nil {
			tactic = t.Tactic
		}
		detections = append(detections, &types.MITREDetection{
			SessionID:   ev.SessionID,
			TechniqueID: id,
			Tactic:      tactic,
			Confidence:  100,
			SourceIP:    ev.SourceIP,
			ServiceType: ev.ServiceType,
			Evidence:    ev.EventType.String(),
			DetectedAt:  detectedAt,
		})
	}
	return detections
}

func (d *Detector) detectSingleEvent(
	ev *types.Event,
) []string {
	var matches []string

	switch ev.EventType {
	case types.EventLoginSuccess:
		matches = append(matches, "T1078")
		if ev.ServiceType == types.ServiceSSH {
			matches = append(matches, "T1021.004")
		}

	case types.EventCommand:
		matches = append(
			matches, d.detectCommand(ev)...,
		)

	case types.EventExploit:
		matches = append(matches, "T1190")

	case types.EventScan:
		matches = append(matches, "T1595")

	case types.EventFileUpload:
		matches = append(matches, "T1105")

	case types.EventConnect:
		if ev.ServiceType == types.ServiceSSH {
			matches = append(matches, "T1133")
		}

	default:
	}

	return matches
}

func (d *Detector) detectCommand(
	ev *types.Event,
) []string {
	cmd := extractCommand(ev.ServiceData)
	if cmd == "" {
		return nil
	}

	var matches []string
	upper := strings.ToUpper(cmd)

	matches = append(matches, "T1059.004")

	if isDiscoveryCommand(upper) {
		matches = append(matches, "T1082")
	}

	if isFileDiscovery(upper) {
		matches = append(matches, "T1083")
	}

	if isNetworkDiscovery(upper) {
		matches = append(matches, "T1016")
	}

	if isProcessDiscovery(upper) {
		matches = append(matches, "T1057")
	}

	if isToolTransfer(upper) {
		matches = append(matches, "T1105")
	}

	if isCronManipulation(upper) {
		matches = append(matches, "T1053.003")
	}

	if isCryptoMining(upper) {
		matches = append(matches, "T1496")
	}

	return matches
}

func (d *Detector) detectMultiEvent(
	ev *types.Event,
) []string {
	d.mu.Lock()
	defer d.mu.Unlock()

	var matches []string
	ip := ev.SourceIP
	now := ev.Timestamp

	s, exists := d.state[ip]
	if !exists {
		s = &ipState{
			services: make(map[types.ServiceType]time.Time),
		}
		d.state[ip] = s
	}

	if ev.EventType == types.EventLoginSuccess ||
		ev.EventType == types.EventLoginFailed {
		s.authHits = append(s.authHits, now)
		s.authHits = pruneWindow(
			s.authHits, now, bruteForceWindow,
		)
		if len(s.authHits) >= bruteForceThreshold {
			matches = append(matches, "T1110")
		}
	}

	if ev.EventType == types.EventConnect {
		s.services[ev.ServiceType] = now
	}

	activeServices := 0
	for svc, ts := range s.services {
		if now.Sub(ts) <= scanWindow {
			activeServices++
		} else {
			delete(s.services, svc)
		}
	}
	if activeServices >= scanThreshold {
		matches = append(matches, "T1046")
	}

	if len(s.authHits) == 0 && len(s.services) == 0 {
		delete(d.state, ip)
	}

	return matches
}

func extractCommand(
	data json.RawMessage,
) string {
	if len(data) == 0 {
		return ""
	}
	var parsed map[string]interface{}
	if json.Unmarshal(data, &parsed) != nil {
		return ""
	}

	if cmd, ok := parsed["command"].(string); ok {
		return cmd
	}
	if q, ok := parsed["query"].(string); ok {
		return q
	}
	return ""
}

func isDiscoveryCommand(cmd string) bool {
	patterns := []string{
		"UNAME", "HOSTNAME", "WHOAMI", "ID",
		"CAT /ETC/PASSWD", "CAT /ETC/SHADOW",
		"CAT /ETC/OS-RELEASE", "CAT /PROC/VERSION",
		"CAT /PROC/CPUINFO", "CAT /PROC/MEMINFO",
		"LSBLK", "LSCPU", "DMIDECODE",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func isFileDiscovery(cmd string) bool {
	patterns := []string{
		"LS ", "LS\t", "DIR ", "FIND ",
		"LOCATE ", "CAT ", "HEAD ", "TAIL ",
	}
	for _, p := range patterns {
		if strings.HasPrefix(cmd, p) {
			return true
		}
	}
	return cmd == "LS" || cmd == "DIR"
}

func isNetworkDiscovery(cmd string) bool {
	patterns := []string{
		"IFCONFIG", "IP ADDR", "IP A",
		"IP ROUTE", "NETSTAT", "SS ",
		"ARP ", "ROUTE ",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func isProcessDiscovery(cmd string) bool {
	patterns := []string{
		"PS ", "PS\t", "TOP", "HTOP",
		"PSTREE", "PGREP ",
	}
	for _, p := range patterns {
		if strings.HasPrefix(cmd, p) ||
			strings.Contains(cmd, p) {
			return true
		}
	}
	return cmd == "PS" || cmd == "W"
}

func isToolTransfer(cmd string) bool {
	patterns := []string{
		"WGET ", "CURL ", "FETCH ",
		"TFTP ", "SCP ", "SFTP ",
		"FTP ", "LWPDOWNLOAD",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func isCronManipulation(cmd string) bool {
	patterns := []string{
		"CRONTAB", "/ETC/CRON",
		"/VAR/SPOOL/CRON",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func isCryptoMining(cmd string) bool {
	patterns := []string{
		"XMRIG", "MINERD", "CPUMINER",
		"STRATUM+TCP", "CRYPTONIGHT",
		"RANDOMX", "KTHREADD",
		"DOTA", ".X11-UNIX",
	}
	for _, p := range patterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}
	return false
}

func pruneWindow(
	times []time.Time, now time.Time, window time.Duration,
) []time.Time {
	cutoff := now.Add(-window)
	var pruned []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	return pruned
}

func dedupStrings(input []string) []string {
	seen := make(map[string]bool, len(input))
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
