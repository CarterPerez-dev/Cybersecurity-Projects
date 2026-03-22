```ruby
██╗  ██╗ █████╗ ███████╗██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗
██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
███████║███████║███████╗███████║██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
██║  ██║██║  ██║███████║██║  ██║╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%238-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/beginner/hash-cracker)
[![C++](https://img.shields.io/badge/C%2B%2B23-00599C?style=flat&logo=cplusplus&logoColor=white)](https://isocpp.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

> Multi-threaded hash cracking tool with dictionary, brute-force, and rule-based mutation attacks.

*This is a quick overview — security theory, architecture, and full walkthroughs are in the [learn modules](#learn).*

## What It Does

- Crack MD5, SHA1, SHA256, and SHA512 hashes with auto-detection from hash length
- Dictionary attacks using memory-mapped wordlists for zero-copy large file handling
- Brute-force attacks with configurable character sets and keyspace partitioning
- Rule-based mutations (capitalize, leet speak, digit append, reverse, toggle case)
- Multi-threaded with zero-contention work partitioning across all CPU cores
- Salt support with prepend/append positioning
- Rich terminal progress display with speed, ETA, and progress bar

## Quick Start

```bash
./install.sh
hashcracker --hash <hash> --wordlist /path/to/rockyou.txt
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | Description |
|---------|-------------|
| `hashcracker --hash <h> --wordlist <path>` | Dictionary attack against a hash |
| `hashcracker --hash <h> --bruteforce --charset lower,digits` | Brute-force with character set |
| `hashcracker --hash <h> --wordlist <path> --rules` | Dictionary + mutation rules |
| `hashcracker --hash <h> --wordlist <path> --salt <s>` | Crack salted hash |
| `hashcracker --help` | Show all options |

## Learn

This project includes step-by-step learning materials covering security theory, architecture, and implementation.

| Module | Topic |
|--------|-------|
| [00 - Overview](learn/00-OVERVIEW.md) | Prerequisites and quick start |
| [01 - Concepts](learn/01-CONCEPTS.md) | Security theory and real-world breaches |
| [02 - Architecture](learn/02-ARCHITECTURE.md) | System design and data flow |
| [03 - Implementation](learn/03-IMPLEMENTATION.md) | Code walkthrough |
| [04 - Challenges](learn/04-CHALLENGES.md) | Extension ideas and exercises |


## License

AGPL 3.0
