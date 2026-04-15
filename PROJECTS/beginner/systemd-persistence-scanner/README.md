```regex
███████╗███████╗███╗   ██╗████████╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝
███████╗█████╗  ██╔██╗ ██║   ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║
███████║███████╗██║ ╚████║   ██║
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%2322-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/systemd-persistence-scanner)
[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Persistence-orange?style=flat)](https://attack.mitre.org/tactics/TA0003/)

> Linux persistence mechanism scanner. Drop a single binary, find every backdoor.

*This is a quick overview. Security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Scans 12+ persistence mechanism categories: systemd, cron, shell profiles, SSH, LD_PRELOAD, kernel modules, udev rules, init.d, XDG autostart, at jobs, MOTD scripts, and PAM modules
- Applies heuristic detection for reverse shells, download-and-execute chains, encoded payloads, alias hijacking, and temp directory abuse
- Severity scoring from info to critical with MITRE ATT&CK technique mapping on every finding
- Baseline mode saves a clean-system snapshot, then highlights only new findings on subsequent runs
- Compiles to a single static binary with zero dependencies for portable deployment

## Quick Start

```bash
go install github.com/CarterPerez-dev/sentinel/cmd/sentinel@latest
sentinel scan
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | Description |
|---------|-------------|
| `sentinel scan` | Scan for all persistence mechanisms |
| `sentinel scan --json` | Output results as structured JSON |
| `sentinel scan --min-severity high` | Only show high and critical findings |
| `sentinel scan --root /mnt/target` | Scan a mounted filesystem or chroot |
| `sentinel baseline save` | Save current state as a clean baseline |
| `sentinel baseline diff` | Show only new findings since baseline |

## Example Output

```
  [CRITICAL] Library in ld.so.preload
         Path: /etc/ld.so.preload
         Evidence: /dev/shm/.evil.so
         MITRE: T1574.006

  [HIGH] Suspicious cron entry: download-and-execute chain
         Path: /etc/cron.d/updater
         Evidence: */5 * * * * root curl http://... | bash
         MITRE: T1053.003

  [MEDIUM] Recently modified unit file
         Path: /etc/systemd/system/backdoor.service
         Evidence: Modified within the last 24 hours
         MITRE: T1543.002

  Summary: 1 critical 1 high 1 medium 0 low 4 info
```

## Scanners

| Scanner | MITRE Technique | What It Checks |
|---------|----------------|----------------|
| systemd | T1543.002, T1053.006 | Service/timer units, ExecStart directives, drop-in overrides |
| cron | T1053.003 | System/user crontabs, cron.d, periodic directories, anacron |
| profile | T1546.004 | Shell RC files, /etc/profile.d, bashrc/zshrc injections |
| ssh | T1098.004 | authorized_keys options, sshd_config, SSH rc scripts |
| ld_preload | T1574.006 | /etc/ld.so.preload, ld.so.conf.d, /etc/environment |
| kernel | T1547.006 | modules-load.d, modprobe.d install hooks |
| udev | T1546 | Udev rules with RUN+= directives |
| initd | T1037.004 | Init.d scripts, rc.local content |
| xdg | T1547.013 | XDG autostart .desktop files |
| atjob | T1053.001 | Pending at job spool |
| motd | T1546 | update-motd.d login scripts |
| pam | T1556.003 | PAM configs, pam_exec.so, pam_permit.so in auth |

## Learn

This project includes step-by-step learning materials covering persistence techniques, detection engineering, and implementation details.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | Linux persistence and MITRE ATT&CK |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design and data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |

## License

AGPL 3.0
