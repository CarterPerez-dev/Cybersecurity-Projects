# Docker Security Concepts

This document explains the security concepts behind the checks that docksec performs. Understanding these helps you know why certain configurations are flagged and how to fix them properly.

## What is the CIS Docker Benchmark

The Center for Internet Security (CIS) publishes security configuration guides called benchmarks. The Docker Benchmark is a 150+ page document that defines security best practices for Docker deployments.

Each control has:
- An ID (like "5.4" for privileged containers)
- A title describing what to check
- A rationale explaining why it matters
- Remediation steps to fix issues
- A severity level (scored vs unscored, Level 1 vs Level 2)

Level 1 controls are basic hardening that should apply to most environments. Level 2 controls provide stronger security but may break functionality.

docksec implements automated checks for controls that can be detected programmatically. Some controls require manual review (like "ensure the container host has been hardened").

## How Docker Isolation Works

Containers are not virtual machines. They share the host kernel. The isolation comes from Linux kernel features:

### Namespaces

Namespaces partition kernel resources so each container sees its own isolated copy:

| Namespace | What it isolates |
|-----------|------------------|
| PID | Process IDs (container sees itself as PID 1) |
| NET | Network interfaces, routing tables, ports |
| MNT | Filesystem mount points |
| UTS | Hostname and domain name |
| IPC | Inter-process communication (shared memory, semaphores) |
| USER | User and group IDs |

When you run `docker run nginx`, Docker creates new namespaces. The nginx process inside cannot see host processes (PID namespace), cannot bind to host network interfaces (NET namespace), and gets its own filesystem view (MNT namespace).

Breaking namespace isolation is a container escape. This is why sharing host namespaces is dangerous:

```bash
# Shares host PID namespace - container can see and signal all host processes
docker run --pid=host nginx

# Shares host network - container has full network access, can bind any port
docker run --network=host nginx
```

### Control Groups (cgroups)

Cgroups limit and account for resource usage:

```bash
# Limit memory to 512MB
docker run --memory=512m nginx

# Limit to 0.5 CPU cores
docker run --cpus=0.5 nginx

# Limit to 100 processes
docker run --pids-limit=100 nginx
```

Without limits, a container can consume all available resources (memory, CPU, disk I/O, PIDs) and crash the host or starve other containers. This is denial of service.

A fork bomb without PID limits:

```bash
# Inside unlimited container
:(){ :|:& };:  # Creates processes until system dies
```

With `--pids-limit=100`, it hits the limit and stops.

## Linux Capabilities

Root traditionally had all privileges. This is too coarse. Linux capabilities break root privileges into smaller units that can be granted independently.

Docker drops most capabilities by default. A container running as root inside still cannot:
- Load kernel modules (CAP_SYS_MODULE)
- Access raw network sockets for sniffing (CAP_NET_RAW)
- Mount filesystems (requires CAP_SYS_ADMIN)

When you add capabilities back, you expand what the container can do:

```bash
# Add ability to change any file ownership
docker run --cap-add=CAP_CHOWN nginx

# Add network administration (modify routing, firewall, sniff traffic)
docker run --cap-add=CAP_NET_ADMIN nginx
```

Some capabilities are critical. Adding these is almost as bad as running privileged:

| Capability | What it allows |
|------------|----------------|
| CAP_SYS_ADMIN | Mount filesystems, namespace operations, many admin tasks |
| CAP_SYS_PTRACE | Debug any process, read memory, inject code |
| CAP_SYS_MODULE | Load kernel modules (instant root on host) |
| CAP_NET_ADMIN | Full network control, MITM attacks |
| CAP_DAC_OVERRIDE | Bypass all file permission checks |

docksec flags any container with these capabilities because they significantly weaken isolation.

### The Privileged Flag

`--privileged` gives all capabilities plus:
- Access to all host devices
- Disables seccomp and AppArmor
- Removes cgroup restrictions

```bash
docker run --privileged nginx
```

This is essentially running on the host with root access. Common scenarios where people use it:
- Running Docker inside Docker (DinD)
- Accessing hardware devices
- Debugging kernel issues

Most of these have safer alternatives. DinD can use `--privileged` on inner containers only. Device access can use `--device` to expose specific devices. Debugging should happen on test systems.

## Security Profiles: seccomp and AppArmor

### seccomp

Seccomp filters system calls. The Linux kernel has around 400 syscalls. Most programs only need a few dozen. Seccomp lets you block the rest.

Docker's default seccomp profile blocks dangerous syscalls:
- `mount` (could escape container filesystem)
- `reboot` (crash the host)
- `kexec_load` (replace running kernel)
- `bpf` (load arbitrary kernel code)

Disabling seccomp removes this protection:

```bash
docker run --security-opt seccomp=unconfined nginx
```

docksec flags `seccomp=unconfined` because it exposes the full syscall attack surface.

### AppArmor

AppArmor is a Mandatory Access Control (MAC) system. Unlike normal permissions (which processes can bypass if running as root), AppArmor rules apply regardless of privilege level.

Docker's default AppArmor profile restricts:
- Writing to certain paths (`/proc`, `/sys`)
- Mounting filesystems
- Accessing raw network

Not having an AppArmor profile means relying only on discretionary controls, which privileged processes can bypass.

## Dangerous Mount Points

Mounting host paths into containers can break isolation:

### The Docker Socket

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock nginx
```

The Docker socket gives full control over the Docker daemon. From inside the container:

```bash
# Start a privileged container that mounts the host root
docker run -v /:/host --privileged alpine chroot /host
```

Game over. You have host root.

docksec flags Docker socket mounts as CRITICAL because they provide trivial container escape.

### Sensitive Host Paths

Some paths are always dangerous to mount:

| Path | Risk |
|------|------|
| `/` | Full host filesystem access |
| `/etc` | Modify passwd, shadow, sudoers, cron |
| `/var/run` | Access to sockets including Docker |
| `/proc` | Kernel and process information, some writable |
| `/sys` | Kernel configuration, some writable |
| `/dev` | Device access |
| `/boot` | Bootloader, kernel images |

Even read-only mounts of `/etc` expose sensitive data (password hashes, private keys).

## no-new-privileges

A process can gain privileges through:
- setuid binaries (`sudo`, `passwd`)
- setgid binaries
- File capabilities

The `no-new-privileges` flag prevents this:

```bash
docker run --security-opt=no-new-privileges nginx
```

Even if an attacker compromises a container and finds a setuid binary, they cannot use it to escalate. This is defense in depth.

## Image Security

### Running as Root

By default, containers run as root (UID 0). This is root inside the container namespace. Without user namespace remapping, it maps to UID 0 on the host.

If an attacker escapes the container, they are root on the host.

Best practice is to create a non-root user:

```dockerfile
RUN useradd -r -u 1000 appuser
USER appuser
```

docksec checks images for USER instructions and flags those running as root.

### Secrets in Images

Docker images are layers. Every instruction creates a layer. Layers are immutable and distributed.

```dockerfile
ENV API_KEY=sk-secret-key-here
```

This secret is baked into the image. Anyone who pulls the image can extract it:

```bash
docker history --no-trunc myimage
```

Even if you delete a secret in a later layer, the earlier layer still contains it:

```dockerfile
COPY secrets.json /app/
RUN rm /app/secrets.json  # Still in previous layer!
```

docksec checks for:
- Secrets in ENV instructions
- Secrets in ARG instructions
- Known secret patterns in build commands

Use BuildKit secrets or runtime injection instead:

```dockerfile
# BuildKit secret mount - not stored in image
RUN --mount=type=secret,id=api_key cat /run/secrets/api_key
```

### ADD vs COPY

```dockerfile
ADD https://example.com/script.sh /app/
ADD archive.tar.gz /app/
```

ADD has implicit behaviors:
- Fetches URLs (could be compromised)
- Auto-extracts archives (zip bombs, symlink attacks)

COPY just copies files. What you see is what you get.

```dockerfile
COPY script.sh /app/
COPY archive.tar.gz /app/  # Copied as-is, not extracted
```

docksec flags ADD usage because COPY is safer and more predictable.

## Network Security

### Inter-Container Communication

By default, containers on the same bridge network can communicate freely. Container A can connect to any port on Container B.

This matters when you run multiple applications. A compromised web container could attack your database container.

The `--icc=false` daemon flag disables this. Containers can only communicate through explicit links or published ports.

### Host Network Mode

```bash
docker run --network=host nginx
```

The container shares the host's network namespace. It can:
- Bind to any port
- See all network interfaces
- Sniff traffic (with CAP_NET_RAW)

This breaks network isolation entirely. Normally used for performance sensitive applications or network tools.

## Compose File Considerations

Compose files can specify all these dangerous options:

```yaml
services:
  app:
    privileged: true  # Full host access
    cap_add:
      - SYS_ADMIN     # Mount filesystems, etc
    network_mode: host  # No network isolation
    volumes:
      - /:/host        # Full filesystem
      - /var/run/docker.sock:/var/run/docker.sock  # Docker control
```

docksec parses compose files and flags the same issues it finds in running containers. This catches problems before deployment.

## The Defense in Depth Model

No single control prevents all attacks. The goal is layered security:

1. **Namespace isolation** - Container cannot see host resources
2. **Capability restrictions** - Container cannot perform privileged operations
3. **seccomp filtering** - Container cannot make dangerous syscalls
4. **AppArmor/SELinux** - Mandatory access control as backup
5. **Resource limits** - Container cannot exhaust host resources
6. **Non-root user** - Compromise gives limited privileges
7. **Read-only filesystem** - Attacker cannot persist changes
8. **No privileged flag** - None of the above is bypassed

docksec checks all these layers. A single CRITICAL finding (like privileged mode) can undermine everything else.

## Further Reading

- [CIS Docker Benchmark v1.6.0](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [Linux Capabilities Manual](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [seccomp Documentation](https://docs.docker.com/engine/security/seccomp/)
- [AppArmor Documentation](https://docs.docker.com/engine/security/apparmor/)
