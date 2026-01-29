# Test Fixtures for Docker Security Audit

This directory contains test fixtures for integration testing of the `docksec` tool.

## Directory Structure

```
testdata/
├── dockerfiles/       # Dockerfile test cases
├── compose/          # Docker Compose test cases
└── containers/       # Container inspect JSON samples
```

---

## Dockerfiles

### Bad Examples (Should Trigger Findings)

#### `bad-secrets.Dockerfile`
**Expected Findings:**
- `CRITICAL`: AWS credentials hardcoded (AWS_SECRET_ACCESS_KEY)
- `CRITICAL`: GitHub token in environment
- `CRITICAL`: Stripe secret key
- `CRITICAL`: OpenAI API key
- `CRITICAL`: Database URL with password
- `HIGH`: API_KEY, PASSWORD, JWT_SECRET in env vars
- `CRITICAL`: Private key content

**Test Purpose:** Verify secret detection in ENV directives and RUN commands

---

#### `bad-root-user.Dockerfile`
**Expected Findings:**
- `MEDIUM`: No USER directive (runs as root)
- `HIGH`: Installing sudo in container
- `MEDIUM`: No HEALTHCHECK defined
- `INFO`: Using apt-get without cleanup in some layers

**Test Purpose:** Verify user privilege checks

---

#### `bad-privileged.Dockerfile`
**Expected Findings:**
- `CRITICAL`: Using `latest` tag
- `HIGH`: Installing Docker CLI (pattern for docker.sock mounting)
- `MEDIUM`: World-writable permissions (chmod 777)
- `MEDIUM`: No USER directive

**Test Purpose:** Verify base image and permission checks

---

#### `bad-add-command.Dockerfile`
**Expected Findings:**
- `MEDIUM`: Using ADD instead of COPY
- `MEDIUM`: No USER directive
- `HIGH`: npm install as root
- `MEDIUM`: No --production flag for npm
- `MEDIUM`: Multiple exposed ports including debug ports (9229, 9230)
- `MEDIUM`: No HEALTHCHECK

**Test Purpose:** Verify Dockerfile best practices

---

### Good Examples (Should Pass)

#### `good-minimal.Dockerfile`
**Expected:** No critical/high findings

**Features:**
- Specific version tag (alpine:3.19)
- Non-root user (appuser, UID 1000)
- Proper file ownership
- HEALTHCHECK present
- Minimal attack surface

---

#### `good-security.Dockerfile`
**Expected:** No findings (perfect security)

**Features:**
- Specific version tag with digest
- Non-root user
- Production dependencies only
- npm cache cleaned
- Immutable filesystem (chmod -R 555)
- HEALTHCHECK
- Tini init process
- Proper signal handling

---

## Docker Compose Files

### Bad Examples

#### `bad-docker-socket.yml`
**Expected Findings:**
- `CRITICAL`: privileged: true
- `CRITICAL`: Docker socket mounted
- `CRITICAL`: /etc/passwd mounted
- `CRITICAL`: /root/.ssh mounted
- `CRITICAL`: CAP_SYS_ADMIN capability
- `CRITICAL`: CAP_NET_ADMIN capability
- `CRITICAL`: CAP_SYS_PTRACE capability
- `MEDIUM`: network_mode: host
- `CRITICAL`: AWS credentials in environment

**Test Purpose:** Most dangerous configuration possible

---

#### `bad-privileged.yml`
**Expected Findings:**
- `CRITICAL`: privileged: true
- `HIGH`: pid: host
- `HIGH`: ipc: host
- `CRITICAL`: Root filesystem mounted (/)
- `CRITICAL`: /proc mounted
- `CRITICAL`: /sys mounted
- `MEDIUM`: No resource limits
- `MEDIUM`: No restart policy

**Test Purpose:** Host namespace access patterns

---

#### `bad-caps.yml`
**Expected Findings:**
- `CRITICAL`: CAP_SYS_MODULE
- `CRITICAL`: CAP_SYS_RAWIO
- `CRITICAL`: CAP_SYS_PTRACE
- `CRITICAL`: CAP_SYS_ADMIN
- `HIGH`: CAP_DAC_OVERRIDE
- `CRITICAL`: CAP_MAC_ADMIN
- `HIGH`: CAP_NET_ADMIN
- `CRITICAL`: CAP_BPF
- `HIGH`: /lib/modules mounted
- `CRITICAL`: /dev mounted

**Test Purpose:** Dangerous Linux capabilities

---

#### `bad-mounts.yml`
**Expected Findings:**
- `CRITICAL`: Docker socket mounted
- `CRITICAL`: Containerd socket mounted
- `CRITICAL`: /etc, /etc/passwd, /etc/shadow mounted
- `CRITICAL`: /root and subdirectories mounted
- `CRITICAL`: Kubernetes directories mounted
- `CRITICAL`: /dev, /proc, /sys mounted
- `HIGH`: /boot, /lib/modules mounted
- `CRITICAL`: /var/lib/docker mounted
- `HIGH`: /var/log mounted

**Test Purpose:** Sensitive filesystem mounts

---

#### `bad-secrets.yml`
**Expected Findings:**
- Multiple `CRITICAL` findings for hardcoded secrets:
  - AWS credentials
  - Database URLs with passwords
  - API keys (Stripe, GitHub, OpenAI, Google, Azure)
  - JWT/Session secrets
  - Private keys
  - Database passwords

**Test Purpose:** Environment variable secret detection

---

#### `bad-no-limits.yml`
**Expected Findings:**
- `MEDIUM`: No memory limits
- `MEDIUM`: No CPU limits
- `MEDIUM`: No PID limits
- `MEDIUM`: No restart policy
- `MEDIUM`: No health check
- `MEDIUM`: No USER directive
- `MEDIUM`: Not read-only filesystem
- `MEDIUM`: No security options
- `MEDIUM`: No capabilities dropped

**Test Purpose:** Resource limits and hardening options

---

### Good Example

#### `good-production.yml`
**Expected:** No critical/high findings

**Features:**
- Specific image tags with versions
- Non-root users (1000:1000, node:node)
- Read-only root filesystem
- Tmpfs for writable directories
- Security options (no-new-privileges, apparmor)
- Capabilities dropped (ALL) then minimal added
- Resource limits (CPU, memory)
- Health checks
- Restart policies
- Network isolation
- Secrets management (not env vars)
- Safe volume mounts (read-only configs)

---

## Container Inspect JSONs

### `privileged-container.json`
**Expected Findings:**
- `CRITICAL`: Privileged mode
- `HIGH`: PID host mode
- `HIGH`: IPC host mode
- `MEDIUM`: Network host mode
- `CRITICAL`: Docker socket mounted
- `CRITICAL`: Multiple dangerous capabilities
- `CRITICAL`: Sensitive host paths mounted
- `CRITICAL`: Secrets in environment
- `MEDIUM`: No resource limits
- `MEDIUM`: No restart policy
- `MEDIUM`: Running as root (empty User)
- `MEDIUM`: No health check

**Test Purpose:** Container runtime configuration checks

---

### `secure-container.json`
**Expected:** No critical/high findings

**Features:**
- Non-privileged
- Non-root user (1000:1000)
- Isolated namespaces (no host mode)
- Capabilities dropped (ALL) + minimal added
- Security options enabled
- Read-only root filesystem
- Tmpfs for writable directories
- Resource limits configured
- Restart policy set
- Health check configured
- Safe volume mounts

**Test Purpose:** Secure container configuration

---

## Usage in Tests

```go
// Example: Test Dockerfile analyzer
func TestDockerfileAnalyzer(t *testing.T) {
    analyzer := analyzer.NewDockerfileAnalyzer()

    // Test bad case
    findings, err := analyzer.Analyze("testdata/dockerfiles/bad-secrets.Dockerfile")
    require.NoError(t, err)
    assert.True(t, findings.HasSeverityAtOrAbove(finding.SeverityCritical))
    assert.Contains(t, findings, "hardcoded-secrets")

    // Test good case
    findings, err = analyzer.Analyze("testdata/dockerfiles/good-security.Dockerfile")
    require.NoError(t, err)
    assert.False(t, findings.HasSeverityAtOrAbove(finding.SeverityHigh))
}
```

---

## Test Matrix

| File | Secrets | Privileged | Caps | Mounts | User | Limits | Health |
|------|---------|-----------|------|--------|------|--------|--------|
| bad-secrets.Dockerfile | ✓ | - | - | - | ✗ | - | ✗ |
| bad-root-user.Dockerfile | - | - | - | - | ✗ | - | ✗ |
| bad-privileged.Dockerfile | - | pattern | - | - | ✗ | - | - |
| bad-add-command.Dockerfile | - | - | - | - | ✗ | - | ✗ |
| bad-docker-socket.yml | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ |
| bad-privileged.yml | - | ✓ | - | ✓ | ✗ | ✗ | ✗ |
| bad-caps.yml | - | - | ✓ | ✓ | ✗ | - | - |
| bad-mounts.yml | - | - | - | ✓ | ✗ | - | - |
| bad-secrets.yml | ✓ | - | - | - | - | - | - |
| bad-no-limits.yml | - | - | - | - | ✗ | ✗ | ✗ |
| good-minimal.Dockerfile | ✗ | ✗ | ✗ | ✗ | ✓ | - | ✓ |
| good-security.Dockerfile | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ | ✓ |
| good-production.yml | ✗ | ✗ | ✓ | ✓ | ✓ | ✓ | ✓ |

Legend:
- ✓ = Has this security feature/issue
- ✗ = Does not have this issue / Has protection
- \- = Not applicable
