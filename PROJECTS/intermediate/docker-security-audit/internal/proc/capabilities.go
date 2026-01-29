/*
CarterPerez-dev | 2026
capabilities.go
*/

package proc

import (
	"fmt"

	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/CarterPerez-dev/docksec/internal/rules"
)

type CapabilitySet struct {
	Effective   uint64
	Permitted   uint64
	Inheritable uint64
	Bounding    uint64
	Ambient     uint64
}

var capabilityBits = map[int]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
	38: "CAP_PERFMON",
	39: "CAP_BPF",
	40: "CAP_CHECKPOINT_RESTORE",
}

var capabilityNames = func() map[string]int {
	m := make(map[string]int, len(capabilityBits))
	for bit, name := range capabilityBits {
		m[name] = bit
	}
	return m
}()

func (c *CapabilitySet) HasCapability(name string) bool {
	bit, ok := capabilityNames[name]
	if !ok {
		return false
	}
	return (c.Effective & (1 << bit)) != 0
}

func (c *CapabilitySet) HasPermitted(name string) bool {
	bit, ok := capabilityNames[name]
	if !ok {
		return false
	}
	return (c.Permitted & (1 << bit)) != 0
}

func (c *CapabilitySet) HasBounding(name string) bool {
	bit, ok := capabilityNames[name]
	if !ok {
		return false
	}
	return (c.Bounding & (1 << bit)) != 0
}

func (c *CapabilitySet) HasAmbient(name string) bool {
	bit, ok := capabilityNames[name]
	if !ok {
		return false
	}
	return (c.Ambient & (1 << bit)) != 0
}

func (c *CapabilitySet) ListEffective() []string {
	return c.listCaps(c.Effective)
}

func (c *CapabilitySet) ListPermitted() []string {
	return c.listCaps(c.Permitted)
}

func (c *CapabilitySet) ListBounding() []string {
	return c.listCaps(c.Bounding)
}

func (c *CapabilitySet) ListAmbient() []string {
	return c.listCaps(c.Ambient)
}

func (c *CapabilitySet) ListInheritable() []string {
	return c.listCaps(c.Inheritable)
}

func (c *CapabilitySet) listCaps(mask uint64) []string {
	var caps []string
	for bit, name := range capabilityBits {
		if (mask & (1 << bit)) != 0 {
			caps = append(caps, name)
		}
	}
	return caps
}

func (c *CapabilitySet) IsFullyPrivileged() bool {
	return c.Effective == 0x1ffffffffff || c.Effective == 0xffffffffffffffff
}

func (c *CapabilitySet) HasDangerousCapabilities() bool {
	for _, cap := range c.ListEffective() {
		if rules.IsDangerousCapability(cap) {
			return true
		}
	}
	return false
}

func (c *CapabilitySet) HasCriticalCapabilities() bool {
	for _, cap := range c.ListEffective() {
		if rules.IsCriticalCapability(cap) {
			return true
		}
	}
	return false
}

func (c *CapabilitySet) GetDangerousCapabilities() []string {
	var dangerous []string
	for _, cap := range c.ListEffective() {
		if rules.IsDangerousCapability(cap) {
			dangerous = append(dangerous, cap)
		}
	}
	return dangerous
}

func (c *CapabilitySet) GetCriticalCapabilities() []string {
	var critical []string
	for _, cap := range c.ListEffective() {
		if rules.IsCriticalCapability(cap) {
			critical = append(critical, cap)
		}
	}
	return critical
}

func (c *CapabilitySet) GetCapabilitiesBySeverity(
	minSeverity finding.Severity,
) []string {
	var result []string
	for _, cap := range c.ListEffective() {
		severity := rules.GetCapabilitySeverity(cap)
		if severity >= minSeverity {
			result = append(result, cap)
		}
	}
	return result
}

func (c *CapabilitySet) EffectiveCount() int {
	return countBits(c.Effective)
}

func (c *CapabilitySet) PermittedCount() int {
	return countBits(c.Permitted)
}

func (c *CapabilitySet) BoundingCount() int {
	return countBits(c.Bounding)
}

func countBits(n uint64) int {
	count := 0
	for n != 0 {
		count += int(n & 1)
		n >>= 1
	}
	return count
}

func ParseCapabilityMask(hex string) (uint64, error) {
	var mask uint64
	_, err := fmt.Sscanf(hex, "%x", &mask)
	return mask, err
}

func CapabilityNameToBit(name string) (int, bool) {
	bit, ok := capabilityNames[name]
	return bit, ok
}

func CapabilityBitToName(bit int) (string, bool) {
	name, ok := capabilityBits[bit]
	return name, ok
}

func AllCapabilityNames() []string {
	names := make([]string, 0, len(capabilityBits))
	for i := 0; i <= 40; i++ {
		if name, ok := capabilityBits[i]; ok {
			names = append(names, name)
		}
	}
	return names
}

var defaultDockerCaps = map[string]struct{}{
	"CAP_CHOWN":            {},
	"CAP_DAC_OVERRIDE":     {},
	"CAP_FSETID":           {},
	"CAP_FOWNER":           {},
	"CAP_MKNOD":            {},
	"CAP_NET_RAW":          {},
	"CAP_SETGID":           {},
	"CAP_SETUID":           {},
	"CAP_SETFCAP":          {},
	"CAP_SETPCAP":          {},
	"CAP_NET_BIND_SERVICE": {},
	"CAP_SYS_CHROOT":       {},
	"CAP_KILL":             {},
	"CAP_AUDIT_WRITE":      {},
}

func (c *CapabilitySet) GetAddedCapabilities() []string {
	var added []string
	for _, cap := range c.ListEffective() {
		if _, isDefault := defaultDockerCaps[cap]; !isDefault {
			added = append(added, cap)
		}
	}
	return added
}

func (c *CapabilitySet) GetDroppedDefaultCapabilities() []string {
	var dropped []string
	for cap := range defaultDockerCaps {
		if !c.HasCapability(cap) {
			dropped = append(dropped, cap)
		}
	}
	return dropped
}

func (c *CapabilitySet) HasOnlyDefaultCapabilities() bool {
	for _, cap := range c.ListEffective() {
		if _, isDefault := defaultDockerCaps[cap]; !isDefault {
			return false
		}
	}
	return true
}
