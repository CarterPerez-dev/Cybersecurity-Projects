# 01-CONCEPTS.md

# Security Concepts

This document covers the security fundamentals behind credential enumeration: what credentials exist on a typical Linux system, where they live, why they're exposed, and what real attackers do with them.

## Credential Exposure and Post-Access Enumeration

### What It Is

Credential exposure is when authentication material (passwords, tokens, private keys, API secrets) is stored in a way that allows unauthorized access. Post-access enumeration is the phase of an attack where, having gained some level of access to a system, the attacker systematically searches for additional credentials to expand their reach.

This is one of the first things attackers do after landing on a machine. Not because it's clever, but because it works. Developer workstations accumulate credentials like lint. AWS keys in `~/.aws/credentials`. SSH private keys without passphrases in `~/.ssh/`. GitHub tokens in `~/.gitconfig`. Database passwords in `~/.pgpass`. Vault tokens in `~/.vault-token`. Most of these files sit there for months or years, rarely audited, often with permissions looser than they need to be.

### Why It Matters

The Uber breach in September 2022 is the textbook example. An 18-year-old attacker purchased stolen credentials from the dark web, bypassed MFA through push notification fatigue, and then found hardcoded credentials in PowerShell scripts on internal network shares. Those credentials gave access to the AWS console, Google Workspace admin, Duo admin panel, and Uber's HackerOne bug bounty dashboard. The initial compromise was social engineering; the escalation was credential harvesting.

The LastPass breach (2022-2023) is even more direct. Attackers compromised a senior DevOps engineer's home machine, found SSH keys and decryption keys stored locally, and used them to access production cloud storage containing encrypted customer vaults. The engineer had legitimate access; the credentials on their home machine provided the path.

In the Codecov supply chain attack (April 2021), the attackers modified a bash uploader script to exfiltrate environment variables from CI/CD pipelines. The leaked variables included tokens, API keys, and credentials that CI systems had access to. Thousands of customers were affected because their build environments had credentials available as environment variables.

### MITRE ATT&CK Mapping

This project directly implements detection for these techniques:

| Technique ID | Name | What We Detect |
|-------------|------|----------------|
| T1552 | Unsecured Credentials | Parent technique for all credential exposure |
| T1552.001 | Credentials In Files | AWS credentials, .pgpass, .my.cnf, .netrc, .git-credentials, .env files |
| T1552.003 | Bash History | Secrets in shell history (export TOKEN=, curl -u), command patterns |
| T1552.004 | Private Keys | SSH keys (encrypted/unencrypted), GCP service account keys |
| T1555 | Credentials from Password Stores | GNOME Keyring, KDE Wallet, KeePass databases, pass store |
| T1555.001 | Keychain | Desktop keyring databases |
| T1555.003 | Credentials from Web Browsers | Firefox logins.json/key4.db, Chromium Login Data |
| T1539 | Steal Web Session Cookie | Firefox cookies.sqlite, Chromium Cookies database |

## Linux File Permissions

### What They Are

Every file on a Linux system has three sets of permissions: owner, group, and others (world). Each set can have read (r=4), write (w=2), and execute (x=1) bits. When you see `0600` on an SSH key, that means the owner can read and write it, but nobody else can see it. When you see `0644`, the owner can read/write but the group and everyone else can read it.

### Why This Is Critical for Credentials

File permissions are the primary defense for credential files on disk. An SSH private key with `0644` permissions means any user on the system can read it. On a shared server, any compromised service running as any user can steal that key. On a single-user workstation, malware running as a different user (or a container escape) gets immediate access.

OpenSSH itself refuses to use a private key with overly permissive permissions. It will print `WARNING: UNPROTECTED PRIVATE KEY FILE!` and refuse to authenticate. But other credential files have no such guard. Your AWS credentials file at `~/.aws/credentials` doesn't care about its own permissions. Neither does `~/.pgpass`, `~/.git-credentials`, or `~/.vault-token`. They'll be read by their respective tools regardless of how exposed they are.

### How the Permission Model Works

```
Permission bits:   Owner   Group   Others
                   rwx     rwx     rwx
0600 =             rw-     ---     ---    (owner read/write only)
0644 =             rw-     r--     r--    (everyone can read)
0700 =             rwx     ---     ---    (owner full access, directory)
0755 =             rwx     r-x     r-x    (everyone can read/enter directory)
```

The permission check hierarchy this tool uses:

| Condition | Severity | Reasoning |
|-----------|----------|-----------|
| World-readable (others has read bit, `0o004`) | CRITICAL | Any user or process on the system can read the file |
| Group-readable (group has read bit, `0o040`) | MEDIUM-HIGH | Users sharing the group can read it; common in shared hosting |
| Looser than expected (e.g., 0644 instead of 0600) | LOW | More permissive than best practice but not immediately exploitable |
| Owner-only (0600 file, 0700 directory) | INFO | Correct permissions, noted for completeness |

### Real World: The Capital One Breach Connection

The 2019 Capital One breach involved a misconfigured WAF that allowed SSRF, which was used to query the EC2 instance metadata service and retrieve IAM role credentials. While that's a cloud-specific attack path, the underlying principle is the same: credentials that are accessible to processes that shouldn't have them. On a Linux workstation, overly permissive file permissions create the same class of exposure at the filesystem level.

## Browser Credential Storage

### How Browsers Store Credentials

Firefox and Chromium-based browsers both store credentials locally in the user's home directory.

**Firefox** uses a profile-based system rooted at `~/.mozilla/firefox/`. Each profile directory contains:
- `logins.json` - Stored usernames and passwords (encrypted with a key from key4.db)
- `key4.db` - NSS key database that holds the encryption key for logins.json
- `cookies.sqlite` - Session cookies that can be used for session hijacking

Firefox profiles are listed in `profiles.ini`. A user might have multiple profiles (personal, work), each with their own credential stores.

**Chromium-based browsers** (Chrome, Brave, Vivaldi, Chromium) store data under `~/.config/<browser>/Default/` (and numbered profiles like `Profile 1`, `Profile 2`):
- `Login Data` - SQLite database of stored passwords
- `Cookies` - Session cookies
- `Web Data` - Autofill data, saved payment methods

On Linux, Chromium encrypts stored passwords using the system keyring (GNOME Keyring or KWallet). Without the keyring unlocked, the encrypted passwords aren't directly usable, but the files still reveal which sites have stored credentials and session cookies may be usable without decryption.

### Why This Matters

The CircleCI breach in January 2023 involved a compromised engineer's laptop where session tokens were stolen from browser storage. Those tokens provided access to CircleCI's internal systems, which in turn held customer secrets (environment variables, API keys, tokens). The attacker didn't need to crack passwords. Session cookies from browser storage were enough.

Browser credential databases being world-readable (0644) is a CRITICAL finding because it means any process on the system can read the encrypted credentials and session cookies. Even with encryption, cookies are often immediately usable for session hijacking.

## SSH Key Security

### How SSH Keys Work

SSH key pairs consist of a private key (stored locally) and a public key (placed on remote servers in `~/.ssh/authorized_keys`). The private key proves your identity. If someone has your private key, they can authenticate as you to any server that trusts the corresponding public key.

Private keys come in several formats:
- OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`) - modern default
- RSA PEM (`-----BEGIN RSA PRIVATE KEY-----`) - legacy format
- ECDSA PEM (`-----BEGIN EC PRIVATE KEY-----`) - elliptic curve
- DSA PEM (`-----BEGIN DSA PRIVATE KEY-----`) - deprecated but still found
- PKCS#8 (`-----BEGIN PRIVATE KEY-----`) - generic wrapper

### Passphrase Protection

Private keys can optionally be encrypted with a passphrase. An encrypted key contains markers like `ENCRYPTED`, `Proc-Type: 4,ENCRYPTED`, `bcrypt`, or `aes256-ctr` in its header. Without the passphrase, the key file is useless to an attacker. But an unencrypted key is immediately usable.

The severity breakdown:

| Key State | Permissions | Severity | Why |
|-----------|------------|----------|-----|
| Unencrypted | World-readable | CRITICAL | Anyone can steal and immediately use the key |
| Encrypted | World-readable | CRITICAL | Passphrase can be brute-forced offline |
| Unencrypted | Owner-only | HIGH | Correct permissions but no defense-in-depth |
| Encrypted | Owner-only | INFO | Both protections in place |

### SSH Config Weaknesses

The SSH config file (`~/.ssh/config`) can also reveal security issues:
- `PasswordAuthentication yes` - allows password-based auth, weaker than key-based
- `StrictHostKeyChecking no` - disables host key verification, enabling machine-in-the-middle attacks
- Host entries reveal which servers the user connects to, giving attackers a target list

### Real World: The Codecov Breach Chain

When Codecov's bash uploader was compromised in 2021, one of the credential types exfiltrated from CI/CD environments was SSH keys. Attackers used stolen SSH keys from Twitch's CI pipeline to access internal Git repositories, which contributed to the massive Twitch source code leak in October 2021. SSH keys found in one environment became the entry point into another.

## Cloud Provider Credentials

### AWS

AWS credentials live in `~/.aws/credentials` in INI format with profiles. Each profile can contain:
- `aws_access_key_id` - starts with `AKIA` for static keys or `ASIA` for temporary session keys
- `aws_secret_access_key` - the secret component
- `aws_session_token` - present for temporary credentials

Static keys (`AKIA`) are long-lived and the highest risk. They work until explicitly rotated or deleted. Session keys (`ASIA`) are temporary but still dangerous during their validity window. The companion file `~/.aws/config` contains profiles, region settings, and optionally SSO or MFA configurations.

A world-readable AWS credentials file is a CRITICAL finding. Any static key found there can be used to make API calls to AWS services with whatever permissions the associated IAM user or role has.

### GCP

Google Cloud credentials are stored in `~/.config/gcloud/`. The most sensitive file is `application_default_credentials.json`, which can contain either user credentials (from `gcloud auth application-default login`) or a service account key (a JSON file with a private key). Service account keys are HIGH severity because they don't expire and often have broad permissions. User credentials are MEDIUM because they're tied to an interactive session and may have short-lived tokens.

### Azure

Azure CLI stores token caches at `~/.azure/accessTokens.json` and `~/.azure/msal_token_cache.json`. These contain OAuth tokens that can be used to make Azure API calls. On a multi-user system, a readable token cache means other users can impersonate the authenticated Azure user.

### Kubernetes

The Kubernetes config at `~/.kube/config` contains cluster contexts, user definitions, and authentication data. This can include:
- Bearer tokens (direct API access)
- Client certificate data (embedded certs)
- Auth provider configurations

A Kubernetes config with bearer tokens is HIGH severity because those tokens often provide cluster-admin or broad namespace access. The 2022 TeamTNT campaign specifically targeted Kubernetes credentials on compromised hosts to spread across container clusters.

## Shell History as an Attack Surface

### What's in Shell History

Shell history files (`~/.bash_history`, `~/.zsh_history`, `~/.fish_history`) record every command typed in a terminal session. Developers routinely type secrets directly into their shells:

**Secret exports:**
```
export API_KEY=sk-proj-abc123...
export DATABASE_URL=postgresql://admin:password@prod.db:5432/app
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Credential-bearing commands:**
```
curl -H "Authorization: Bearer ghp_xxxx" https://api.github.com/repos
curl -u admin:s3cret https://internal-api.corp.net/deploy
mysql -u root -pMyPassword production_db
sshpass -p 'server_pass' ssh deploy@prod.server.com
```

These entries persist in history files indefinitely unless explicitly cleared. On a compromised workstation, shell history is one of the first places an attacker checks.

### Environment Files

Beyond shell history, `.env` files scattered across project directories contain application secrets. These files follow the `KEY=value` pattern and are used by frameworks and tools to load configuration. A recursive scan of the home directory commonly finds `.env`, `.env.local`, `.env.production`, and `.env.staging` files containing database passwords, API keys, and service tokens.

### Real World: The Dropbox Breach

In November 2022, Dropbox disclosed that an attacker accessed 130 internal GitHub repositories after a phishing attack. The investigation found that the attacker obtained credentials that were stored in environment configuration used by CI/CD systems. The pattern is consistent: credentials in configuration files, accessible after initial access.

## Keyrings and Password Managers

### Desktop Keyrings

Linux desktop environments provide system-level credential storage:

**GNOME Keyring** (`~/.local/share/keyrings/`) stores passwords, SSH key passphrases, and application secrets in `.keyring` files. The default keyring is unlocked when the user logs in and stays unlocked for the session. If the keyring files are readable by other users, the encrypted contents can be exfiltrated for offline attack.

**KDE Wallet** (`~/.local/share/kwalletd/`) serves the same purpose for KDE desktops.

### Password Manager Databases

**KeePass** databases (`.kdbx` files) can exist anywhere in the home directory. They're encrypted with a master password (and optionally a key file), but finding a KeePass database tells an attacker that a password vault exists and is worth targeting. The database file plus a keylogger for the master password gives access to every stored credential.

**pass** (password-store) at `~/.password-store/` uses GPG-encrypted files organized as directories. Each `.gpg` file is one credential. The number of entries reveals the scope of stored credentials.

**Bitwarden** stores local vault data at `~/.config/Bitwarden/` and `~/.config/Bitwarden CLI/`. Like KeePass, the vault is encrypted, but its presence and accessibility are worth documenting.

## Git Credential Storage

### Plaintext Git Credentials

The file `~/.git-credentials` stores credentials in plaintext URL format: `https://user:token@github.com`. This file is created when using the `store` credential helper (`git config credential.helper store`). Each line is a full URL with embedded authentication. This is HIGH severity by default and CRITICAL if world-readable.

### Credential Helpers

Git config files (`~/.gitconfig`, `~/.config/git/config`) specify credential helpers. The `store` helper saves to `.git-credentials` in plaintext. Other helpers like `cache` (temporary in-memory), `osxkeychain`, or `gnome-keyring` are more secure but their configuration still reveals how the user manages Git authentication.

### Token Patterns

GitHub personal access tokens follow known prefixes: `ghp_` (classic PAT), `gho_` (OAuth), `ghu_` (user-to-server), `ghs_` (server-to-server), `ghr_` (refresh). GitLab tokens start with `glpat-`. Finding these patterns in Git config files means tokens have been hardcoded, likely inadvertently.

### Real World: The Mercedes-Benz Leak

In January 2024, security researchers found a GitHub token in a public Mercedes-Benz repository that provided unrestricted access to the company's internal GitHub Enterprise Server. The token, likely committed by mistake, exposed source code, cloud access keys, blueprints, and internal design documents. This is the exact class of exposure Git credential scanning detects.

## Application Tokens and Database Credentials

### Database Credential Files

Several database clients support credential files in the home directory:

- `~/.pgpass` - PostgreSQL password file. Format: `hostname:port:database:username:password`, one entry per line. PostgreSQL enforces 0600 permissions on this file, but doesn't prevent the file from existing with worse permissions
- `~/.my.cnf` - MySQL client configuration. Can contain `[client]` sections with `password=` entries
- `~/.rediscli_auth` - Redis CLI authentication credentials
- `~/.mongorc.js` - MongoDB shell startup file, may contain authentication commands

### Development Tokens

- `~/.npmrc` - npm registry authentication. Contains `_authToken=` for package publishing
- `~/.pypirc` - PyPI credentials for publishing Python packages
- `~/.config/gh/hosts.yml` - GitHub CLI OAuth tokens

### Infrastructure Tokens

- `~/.terraform.d/credentials.tfrc.json` - Terraform Cloud API tokens
- `~/.vault-token` - HashiCorp Vault authentication token
- `~/.config/helm/repositories.yaml` - Helm chart repository credentials
- `~/.config/rclone/rclone.conf` - Rclone cloud storage credentials (may contain OAuth tokens or API keys)
- `~/.docker/config.json` - Docker registry authentication tokens

### Application Data

Desktop applications store session data locally:
- Slack (`~/.config/Slack/`) - Workspace session tokens
- Discord (`~/.config/discord/`) - Authentication tokens
- VS Code (`~/.config/Code/`) - Extension credentials, potentially including SSH keys and API tokens in settings

## Common Pitfalls

**Assuming encryption means safety.** An encrypted SSH key with 0644 permissions is still a CRITICAL finding. The encrypted key can be exfiltrated and the passphrase brute-forced offline with tools like John the Ripper. Encryption is defense-in-depth, not a substitute for proper permissions.

**Ignoring "just config" files.** AWS config (`~/.aws/config`) doesn't contain secrets directly, but it reveals account structure, regions, and whether MFA is required. Kubernetes config without tokens still shows cluster endpoints and namespaces. This reconnaissance data helps attackers plan further exploitation.

**Forgetting about temporary files.** Shell history accumulates over time. A secret exported six months ago is still in `.bash_history` unless manually cleaned. Environment files in project directories may have been created during development and never removed after deployment.

**Trusting single-user systems.** "I'm the only user on this machine" doesn't mean credentials are safe. Malware, container escapes, browser exploits, and compromised applications all run as processes with some level of file system access. World-readable credentials are accessible to all of them.

## How These Concepts Relate

```
                            ┌──────────────────────┐
                            │   Initial Access      │
                            │  (phishing, exploit,  │
                            │   stolen creds, etc)  │
                            └──────────┬───────────┘
                                       │
                                       ▼
                            ┌──────────────────────┐
                            │  Post-Access          │
                            │  Enumeration          │
                            │  (this tool)          │
                            └──────────┬───────────┘
                                       │
              ┌──────────────┬─────────┼─────────┬────────────────┐
              ▼              ▼         ▼         ▼                ▼
      ┌──────────────┐ ┌─────────┐ ┌───────┐ ┌─────────┐ ┌───────────┐
      │ SSH Keys     │ │ Cloud   │ │ Git   │ │ Browser │ │ App       │
      │ T1552.004    │ │ T1552.001│ │Tokens │ │ T1555.003│ │ Tokens    │
      └──────┬───────┘ └────┬────┘ └───┬───┘ └────┬────┘ └─────┬─────┘
             │              │          │           │            │
             ▼              ▼          ▼           ▼            ▼
      ┌──────────────┐ ┌─────────┐ ┌───────┐ ┌─────────┐ ┌───────────┐
      │ Lateral      │ │ Cloud   │ │ Source │ │ Session │ │ Database  │
      │ Movement     │ │ Pivot   │ │ Code  │ │ Hijack  │ │ Access    │
      │              │ │         │ │ Access │ │         │ │           │
      └──────────────┘ └─────────┘ └───────┘ └─────────┘ └───────────┘
```

Each credential type enables a different escalation path. SSH keys enable lateral movement to other servers. Cloud credentials pivot into cloud infrastructure. Git tokens expose source code repositories. Browser cookies enable session hijacking. Application tokens give direct access to databases and services.

The common thread is file permissions. Every finding in this tool comes down to: is the credential file accessible to more entities than it should be, and is the credential itself protected (encrypted, passphrase-protected) or in plaintext?

## Testing Your Understanding

Before moving to the architecture, make sure you can answer:

1. Why is an unencrypted SSH key with 0600 permissions rated HIGH rather than CRITICAL? What would push it to CRITICAL?
2. An attacker finds `~/.aws/credentials` with two profiles: one using `AKIA` keys and one using `ASIA` keys. Which is more concerning and why?
3. Why does this tool scan for `.env` files recursively but limits depth to 5 directories? What would happen without a depth limit?
4. A Firefox logins.json file is encrypted. Why is it still a finding?
5. How does shell history scanning differ from environment file scanning in terms of what's detected and why the severity differs?

## Further Reading

**Essential:**
- [MITRE ATT&CK: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) - The framework mapping for everything this tool detects
- [MITRE ATT&CK: Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/) - Browser and keyring credential theft
- [CIS Benchmarks for Linux](https://www.cisecurity.org/benchmark/distribution_independent_linux) - File permission hardening recommendations

**Deep Dives:**
- [Uber Security Incident Report (2022)](https://www.uber.com/newsroom/security-update/) - Post-access credential harvesting in practice
- [CircleCI Security Incident (2023)](https://circleci.com/blog/jan-4-2023-incident-report/) - Browser token theft leading to platform compromise
- [LastPass Security Incident (2022-2023)](https://blog.lastpass.com/2023/03/security-incident-update-recommended-actions/) - Home machine credential theft leading to production breach

**Historical Context:**
- [Codecov Supply Chain Attack (2021)](https://about.codecov.io/security-update/) - Environment variable exfiltration at scale
- [Twitch Source Code Leak (2021)](https://blog.twitch.tv/en/2021/10/06/updates-on-the-twitch-security-incident/) - Stolen credentials enabling source code access
