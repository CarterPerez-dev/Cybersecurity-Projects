# DNS Lookup Tool

Professional DNS lookup CLI with beautiful Rich terminal output. Query DNS records, perform reverse lookups, trace resolution paths, and retrieve WHOIS information.

## Features

- **Multi-Record Queries**: Query A, AAAA, MX, NS, TXT, CNAME, SOA records
- **Reverse DNS**: IP to hostname resolution
- **DNS Trace**: Visualize the resolution path from root to authoritative servers
- **Batch Lookups**: Query multiple domains concurrently
- **WHOIS Integration**: Domain registration information
- **JSON Export**: Machine-readable output for scripting
- **Beautiful Output**: Color-coded tables, spinners, and tree visualizations

## Installation

```bash
# Clone the repository
git clone https://github.com/CarterPerez-dev/Cybersecurity-Projects.git
cd PROJECTS/dns-lookup

# Install with uv
uv sync

# Or install with pip

python -m venv .venv

source .venv/bin/activate

pip install -e .
```

## Usage

### Basic DNS Query

```bash
# Query all record types
dnslookup query example.com

# Query specific record types
dnslookup query example.com --type A,MX,TXT

# Use custom DNS server
dnslookup query example.com --server 8.8.8.8

# Output as JSON
dnslookup query example.com --json
```

### Reverse DNS Lookup

```bash
# IPv4
dnslookup reverse 8.8.8.8

# IPv6
dnslookup reverse 2606:4700:4700::1111
```

### DNS Trace

Trace the resolution path from root servers to authoritative nameservers:

```bash
dnslookup trace example.com
dnslookup trace example.com --type MX
```

### Batch Lookups

Query multiple domains from a file:

```bash
# Create a file with domains (one per line)
echo -e "google.com\ngithub.com\ncloudflare.com" > domains.txt

# Run batch lookup
dnslookup batch domains.txt

# Save results to JSON
dnslookup batch domains.txt --output results.json
```

### WHOIS Lookup

```bash
dnslookup whois example.com
dnslookup whois google.com --json
```

## Example Output

### DNS Query
```
🌐 DNS Lookup: example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

┌──────────────────────────────────────────┐
│ DNS Records                              │
├──────┬───────────────────────┬───────────┤
│ Type │ Value                 │ TTL       │
├──────┼───────────────────────┼───────────┤
│ A    │ 93.184.216.34         │ 1h        │
│ AAAA │ 2606:2800:220:1:...   │ 1h        │
│ MX   │ mail.example.com (10) │ 1d        │
│ NS   │ ns1.example.com       │ 2d        │
└──────┴───────────────────────┴───────────┘

✓ Found 8 records in 45ms
```

### DNS Trace
```
🔍 DNS Trace: example.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌍 DNS Resolution Path
├── [.] Root
│   └── → a.root-servers.net (198.41.0.4)
│       └── Referred to com. servers
├── [com.] TLD
│   └── → a.gtld-servers.net (192.5.6.30)
│       └── Referred to example.com NS
└── [example.com.] Authoritative
    └── → ns1.example.com (93.184.216.34)
        └── A: 93.184.216.34

✓ Resolution complete: 93.184.216.34
```

## Development

```bash
# Install dev dependencies
just install-dev

# Run the tool
just run query example.com

# Run tests
just test

# Lint code
just lint

# Format code
just ruff-fix

# Run all checks
just ci
```

## Available Commands

| Command | Description |
|---------|-------------|
| `just run *ARGS` | Run the CLI tool |
| `just test` | Run test suite |
| `just lint` | Run ruff linter |
| `just ruff-fix` | Auto-fix and format |
| `just mypy` | Type checking |
| `just ci` | Run all checks |
| `just clean` | Remove cache files |


## License

MIT License - See LICENSE for details.

## Author

CarterPerez-dev
