```regex
███████╗ █████╗ ███████╗████████╗ █████╗ ██████╗ ██╗     ██╗  ██╗██████╗  ██████╗
██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║     ██║  ██║╚════██╗██╔═████╗
█████╗  ███████║███████╗   ██║   ███████║██████╔╝██║     ███████║ █████╔╝██║██╔██║
██╔══╝  ██╔══██║╚════██║   ██║   ██╔══██║██╔═══╝ ██║     ╚════██║██╔═══╝ ████╔╝██║
██║     ██║  ██║███████║   ██║   ██║  ██║██║     ██║          ██║███████╗╚██████╔╝
╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝          ╚═╝╚══════╝ ╚═════╝
```

[![Cybersecurity Projects](https://img.shields.io/badge/Cybersecurity--Projects-Project%20%235-red?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/advanced/api-rate-limiter)
[![Python](https://img.shields.io/badge/Python-3.14+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![PyPI](https://img.shields.io/pypi/v/fastapi-420?color=3775A9&logo=pypi&logoColor=white)](https://pypi.org/project/fastapi-420)
[![FastAPI](https://img.shields.io/badge/FastAPI-compatible-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)

> Enterprise rate limiting for FastAPI using HTTP 420 "Enhance Your Calm".

*Learning Docs are here: [learn modules](#learn).*

## What It Does

- Three implementation methods: middleware (global), decorator (per route), dependency injection
- Sliding Window, Token Bucket, and Fixed Window rate limiting algorithms
- Redis support with automatic in-memory fallback when Redis is unavailable
- Scoped rate limiters for applying different limits to endpoint groups
- Fingerprint levels (RELAXED, NORMAL, STRICT) for client identification granularity
- Multiple stacking rules where the most restrictive limit applies

## Quick Start

```bash
uv add fastapi-420
```

```python
from fastapi import FastAPI
from fastapi_420 import RateLimiter, RateLimiterSettings

app = FastAPI()
limiter = RateLimiter(RateLimiterSettings(default_limit="69/minute"))
app.add_middleware(limiter.middleware)
```

For Redis support: `uv add fastapi-420[redis]`

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

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
