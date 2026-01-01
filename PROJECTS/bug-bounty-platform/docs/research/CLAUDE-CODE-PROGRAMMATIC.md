# Claude Code Programmatic Usage Research

**Research Date:** 2025-12-14
**Purpose:** Comprehensive investigation of using Claude Code programmatically as a backend API for FastAPI applications

---

## Executive Summary

Claude Code can be used programmatically through three primary approaches:

1. **CLI with `-p` flag** - Direct subprocess calls for simple automation
2. **Claude Agent SDK** - Production-ready library (Python/TypeScript) that wraps the CLI
3. **FastAPI Integration** - REST API wrapper around Claude Code execution

**Key Finding:** The Claude Agent SDK (formerly Claude Code SDK) is the recommended approach for FastAPI backend integration. It spawns the Claude CLI as a subprocess and handles authentication, tool execution, session management, and streaming automatically.

**Context Access:** Claude Code can access database/application context through:
- **Direct prompt strings** (simple, works immediately)
- **MCP servers** (advanced, for repeated database access and efficient token usage)
- **Combination approach** (MCP for data sources, prompts for specific queries)

**Authentication:** Production deployments should use `ANTHROPIC_API_KEY` environment variable for pay-per-use API billing. Subscription-based authentication requires browser OAuth and is not suitable for headless server environments.

---

## 1. Calling Claude Code from Python Backend

### Solution Summary

Use the **Claude Agent SDK for Python** rather than raw subprocess calls. The SDK provides a production-ready abstraction over the Claude Code CLI with built-in tool execution, session management, and streaming support.

### Detailed Analysis

#### Understanding the Architecture

The Claude Agent SDK follows this architecture:

```
Your FastAPI App → Claude Agent SDK (Python) → Claude CLI (subprocess) → Anthropic API
```

> "The SDK spawns the CLI as a subprocess; the CLI talks to the Anthropic API." - [Claude Code Python SDK](https://adrianomelo.com/posts/claude-code-python-sdk.html)

The SDK abstracts subprocess management, JSON streaming, and message parsing while providing a rich type system for structured interactions.

#### Installation and Setup

**Step 1: Install Claude Code CLI**

```bash
# macOS/Linux/WSL
curl -fsSL https://claude.ai/install.sh | bash

# Or via npm
npm install -g @anthropic-ai/claude-code

# Or via Homebrew (macOS)
brew install --cask claude-code
```

**Step 2: Install Claude Agent SDK**

```bash
pip install claude-agent-sdk
```

**Step 3: Set Authentication**

```bash
export ANTHROPIC_API_KEY=your-api-key-here
```

Get your API key from the [Anthropic Console](https://console.anthropic.com/).

#### Basic Usage Pattern

```python
import asyncio
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    async for message in query(
        prompt="Find and fix the bug in auth.py",
        options=ClaudeAgentOptions(allowed_tools=["Read", "Edit", "Bash"])
    ):
        print(message)

asyncio.run(main())
```

#### FastAPI Integration Example

```python
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from claude_agent_sdk import query, ClaudeAgentOptions
import asyncio

app = FastAPI()

class PromptRequest(BaseModel):
    prompt: str
    context: str | None = None

class ClaudeResponse(BaseModel):
    content: str
    session_id: str | None = None

@app.post("/api/claude/generate", response_model=ClaudeResponse)
async def generate_content(request: PromptRequest):
    full_prompt = f"{request.context}\n\n{request.prompt}" if request.context else request.prompt

    result_content = ""
    session_id = None

    async for message in query(
        prompt=full_prompt,
        options=ClaudeAgentOptions(
            allowed_tools=["Read", "Write", "Edit", "Bash"],
            permission_mode="bypassPermissions"
        )
    ):
        if hasattr(message, 'content'):
            result_content += str(message.content)
        if hasattr(message, 'session_id'):
            session_id = message.session_id

    return ClaudeResponse(content=result_content, session_id=session_id)
```

### Alternative Approach: Direct CLI Usage

For simpler use cases, you can call the CLI directly using the `-p` flag:

```python
import subprocess
import json

def call_claude_cli(prompt: str) -> dict:
    """
    Call Claude Code CLI with -p flag for headless execution
    """
    proc = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "json"],
        capture_output=True,
        text=True,
        timeout=300
    )

    if proc.returncode == 0:
        return json.loads(proc.stdout)
    else:
        raise RuntimeError(f"Claude CLI failed: {proc.stderr}")

result = call_claude_cli("What files are in this directory?")
```

**CLI Flags for Programmatic Use:**

| Flag | Purpose |
|------|---------|
| `-p` or `--print` | Non-interactive mode, prints response and exits |
| `--output-format json` | Structured JSON output for parsing |
| `--output-format stream-json` | Streaming JSON events |
| `--max-turns N` | Limit agentic turns in non-interactive mode |
| `--verbose` | Enable verbose logging for debugging |
| `--system-prompt "text"` | Replace entire system prompt |
| `--append-system-prompt "text"` | Add to default prompt |

### Production Best Practices

1. **Use the SDK over raw subprocess calls** - Better error handling, type safety, session management
2. **Set timeouts** - Prevent hanging requests
3. **Handle streaming** - Process responses incrementally for better UX
4. **Use async/await** - Leverage FastAPI's async capabilities
5. **Implement retry logic** - Handle API rate limits and transient failures
6. **Monitor token usage** - Track costs and optimize context

---

## 2. Database/Context Access for Programmatic Claude Code

### Solution Summary

Claude Code has two primary methods for accessing database and application context:

1. **Direct Prompt Strings** - Pass context directly in the prompt (simple, immediate)
2. **MCP Servers** - Connect to databases via Model Context Protocol (efficient, reusable)

For production FastAPI backends, a **hybrid approach** works best: use MCP servers for persistent database connections and direct prompts for specific query parameters.

### Detailed Analysis

#### Method 1: Passing Context via Prompt Strings

**How It Works:**

> "Claude Code supports several methods for providing data: copy and paste directly into prompts (the most common approach), piping into Claude Code (e.g., cat foo.txt | claude) for logs, CSVs, and large data, or telling Claude to pull data via bash commands." - [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices)

**Example: FastAPI Backend Loading Database Context**

```python
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession
from claude_agent_sdk import query, ClaudeAgentOptions

@app.post("/api/generate-email")
async def generate_email(user_id: int, db: AsyncSession):
    user = await db.execute(
        select(User).where(User.id == user_id)
    )
    user_data = user.scalar_one()

    context = f"""
    User Information:
    - Name: {user_data.name}
    - Email: {user_data.email}
    - Purchase History: {user_data.orders}
    - Preferences: {user_data.preferences}
    """

    prompt = "Write a personalized marketing email for this user"

    async for message in query(
        prompt=f"{context}\n\n{prompt}",
        options=ClaudeAgentOptions(allowed_tools=[])
    ):
        # Process response
        pass
```

**Advantages:**
- Simple and straightforward
- Works immediately without setup
- Full control over context

**Disadvantages:**
- Repetitive data loading for similar queries
- Can consume large amounts of tokens
- No caching or optimization

> "Loading entire directories into Claude for every request can be very expensive." - [Claude Context Optimization](https://github.com/zilliztech/claude-context)

#### Method 2: MCP Server for Database Access

**How It Works:**

> "Claude Code can connect to hundreds of external tools and data sources through the Model Context Protocol (MCP), an open source standard for AI-tool integrations, giving Claude Code access to tools, databases, and APIs." - [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp)

**MCP Architecture:**

```
Claude Code (Client) → MCP Server → Your Database/API
```

The MCP server exposes database operations as "tools" that Claude Code can call programmatically.

**Example: Database MCP Server**

> "DBHub by Bytebase is an open-source MCP server that can expose databases (Postgres, MySQL, etc.) to Claude, allowing Claude to directly query the database for schema info or even data." - [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices)

**Setting Up MCP Server for PostgreSQL:**

```python
from claude_agent_sdk import query, ClaudeAgentOptions

async def main():
    async for message in query(
        prompt="Find emails of 10 random users who used feature ENG-4521",
        options=ClaudeAgentOptions(
            mcp_servers={
                "postgres": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"],
                    "env": {
                        "POSTGRES_URL": "postgresql://user:pass@localhost:5432/db"
                    }
                }
            }
        )
    ):
        print(message)
```

**Token Efficiency:**

> "Instead of loading entire directories into Claude for every request, Claude Context efficiently stores your codebase in a vector database and only uses related code in context to keep costs manageable." - [Claude Context](https://github.com/zilliztech/claude-context)

**Context Usage Comparison:**

- **With all MCP tools enabled:** 143k/200k tokens (72%) - MCP tools consuming 82.0k tokens (41.0%)
- **With selective MCP tools:** 67k/200k tokens (34%) - MCP tools taking only 5.7k tokens (2.8%)

#### Method 3: Hybrid Approach (Recommended for FastAPI)

**Best Practice Pattern:**

1. Configure MCP server for database connection (one-time setup)
2. Pass specific query parameters via prompt
3. Let Claude use MCP tools to fetch relevant data
4. Claude processes and returns results

**Example Implementation:**

```python
from fastapi import FastAPI
from claude_agent_sdk import query, ClaudeAgentOptions

app = FastAPI()

@app.post("/api/claude/analyze-users")
async def analyze_users(feature_id: str):
    async for message in query(
        prompt=f"Analyze user engagement for feature {feature_id} using the database",
        options=ClaudeAgentOptions(
            mcp_servers={
                "postgres": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"],
                    "env": {
                        "POSTGRES_URL": os.getenv("DATABASE_URL")
                    }
                }
            },
            allowed_tools=["Read", "Bash"]
        )
    ):
        # Process streaming response
        pass
```

### When to Use Which Approach

| Use Case | Recommended Method | Reason |
|----------|-------------------|--------|
| One-off queries with small data | Direct prompt | Simple, no setup needed |
| Repeated database queries | MCP server | Token efficient, reusable |
| Large datasets | MCP server | Avoids context window limits |
| Mixed sources (DB + files + APIs) | Hybrid | Best of both worlds |
| Production FastAPI backend | Hybrid | Flexible and efficient |

---

## 3. MCP Server Architecture for Programmatic Usage

### Solution Summary

When using Claude Code programmatically via subprocess/SDK, you do **NOT** need to mount MCP servers on your FastAPI app (no `app.mount("/mcp", mcp)`). Instead, MCP servers are configured **within the Claude Agent SDK options** and run as separate processes that Claude Code connects to directly.

### Detailed Analysis

#### Understanding "Who Calls Who"

**Critical Distinction:**

1. **fastapi-mcp** - Exposes your FastAPI endpoints AS MCP tools FOR Claude to call
2. **Claude Agent SDK mcp_servers option** - Connects Claude TO external MCP servers

These are two different patterns:

**Pattern A: Claude calls your FastAPI tools (via fastapi-mcp)**
```
User → Claude Desktop → MCP Proxy → Your FastAPI App (with fastapi-mcp)
```

**Pattern B: Your FastAPI app calls Claude (which uses MCP servers)**
```
User → Your FastAPI App → Claude Agent SDK → Claude CLI → External MCP Server → Database
```

For your use case (FastAPI backend calling Claude Code), you want **Pattern B**.

#### MCP Server Architecture Explanation

> "The Model Context Protocol defines a client-server architecture for tool use. An MCP server wraps an external service or data source behind a common protocol (with defined actions, or 'tools'), while an MCP client (like Claude Code or other AI agent frameworks) connects to the server to invoke those tools." - [Claude Code as an MCP Server](https://www.ksred.com/claude-code-as-an-mcp-server-an-interesting-capability-worth-understanding/)

**Call Flow:**

```
1. User clicks button in React
2. React → FastAPI endpoint
3. FastAPI → Claude Agent SDK (query function)
4. SDK spawns Claude CLI subprocess
5. Claude CLI connects to MCP server (separate process)
6. MCP server queries PostgreSQL
7. Results flow back through the chain
```

> "Client sends user message to the model. Model analyzes context and decides to call a tool exposed by MCP (or multiple tools). Client forwards the tool call to the MCP server over the chosen transport. Server executes the tool and returns results. Model receives tool output and composes the final answer to the user." - [Create a MCP Server for Claude Code](https://www.cometapi.com/create-a-mcp-server-for-claude-code/)

#### Configuration in FastAPI Backend

**You configure MCP servers in the SDK options, not on the FastAPI app:**

```python
from fastapi import FastAPI
from claude_agent_sdk import query, ClaudeAgentOptions
import os

app = FastAPI()

@app.post("/api/generate")
async def generate_content(prompt: str):
    async for message in query(
        prompt=prompt,
        options=ClaudeAgentOptions(
            mcp_servers={
                "postgres": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"],
                    "env": {
                        "POSTGRES_URL": os.getenv("DATABASE_URL")
                    }
                },
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/allowed/path"]
                }
            }
        )
    ):
        yield message
```

**No `app.mount("/mcp", mcp)` needed** because:
- MCP servers are spawned as child processes by the Claude CLI
- They communicate via stdio/SSE/HTTP transports
- They're not part of your FastAPI application's HTTP routes

#### When Would You Use fastapi-mcp?

You would use `fastapi-mcp` if you wanted to **expose your FastAPI endpoints to Claude Desktop/CLI as tools**:

```python
from fastapi import FastAPI
from fastapi_mcp import FastApiMCP

app = FastAPI()

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"user": user_id}

mcp = FastApiMCP(app=app)
mcp.mount()

```

Then configure Claude Desktop to use your API:

```json
{
  "mcpServers": {
    "my-api": {
      "command": "mcp-proxy",
      "args": ["http://localhost:8000/mcp"]
    }
  }
}
```

> "The mcp-proxy proxies requests to a remote MCP server over SSE transport, wrapping your real server and translating Claude's SSE-based requests into regular HTTP requests that your FastAPI app understands." - [FastAPI-MCP Quick Start](https://thedocs.io/fastapi_mcp/quick_start/)

**This is NOT what you want for your use case.** You want Claude Code to call external MCP servers (like database), not to call your FastAPI app.

#### Claude Code as Both MCP Client and Server

Interestingly, Claude Code can act as both:

> "You can run claude mcp serve to expose Claude Code while Claude Code itself connects to GitHub and Postgres MCP servers. This means Claude Code can act as **both** an MCP client and an MCP server simultaneously, allowing for layered agent architectures." - [Claude Code as an MCP Server](https://www.ksred.com/claude-code-as-an-mcp-server-an-interesting-capability-worth-understanding/)

But for your FastAPI backend use case, Claude Code is purely an MCP **client** connecting to database/tool servers.

---

## 4. Production Deployment Considerations

### Solution Summary

For production deployment of Claude Code in a FastAPI backend:

1. **Container Strategy:** Same container as FastAPI (simpler) or separate container (better isolation)
2. **Authentication:** Use `ANTHROPIC_API_KEY` environment variable (not subscription-based OAuth)
3. **Billing:** API pay-per-use is recommended for production over subscription plans
4. **Headless Mode:** Fully supported via environment variable authentication

### Detailed Analysis

#### Container Deployment Options

**Option 1: Same Container (Recommended for MVP)**

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y curl && \
    curl -fsSL https://claude.ai/install.sh | bash

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
ENV DATABASE_URL=${DATABASE_URL}

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Advantages:**
- Simpler deployment
- Fewer network hops
- Lower latency

**Disadvantages:**
- Larger container image
- Tight coupling

**Option 2: Separate Container (Recommended for Production)**

```yaml

services:
  backend:
    build: ./backend
    environment:
      - CLAUDE_SERVICE_URL=http://claude-service:8001
    depends_on:
      - claude-service
      - postgres

  claude-service:
    build: ./claude-service
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    volumes:
      - ./workspace:/workspace

  postgres:
    image: postgres:16
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
```

**Claude Service Implementation:**

```python

from fastapi import FastAPI
from claude_agent_sdk import query, ClaudeAgentOptions

app = FastAPI()

@app.post("/execute")
async def execute_claude(prompt: str, context: dict = None):
    async for message in query(
        prompt=prompt,
        options=ClaudeAgentOptions(
            mcp_servers={
                "postgres": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"],
                    "env": {"POSTGRES_URL": os.getenv("DATABASE_URL")}
                }
            }
        )
    ):
        yield message
```

**Advantages:**
- Better isolation
- Independent scaling
- Cleaner architecture
- Can reuse claude-service across multiple apps

#### Authentication in Containerized Environments

**Critical Finding:** Subscription-based authentication (Claude Pro/Max) is NOT suitable for production containers.

> "The SDK also supports authentication via third-party API providers like Amazon Bedrock (set CLAUDE_CODE_USE_BEDROCK=1 environment variable) and Google Vertex AI (set CLAUDE_CODE_USE_VERTEX=1 environment variable)." - [Claude Code SDK Python Authentication](https://support.claude.com/en/articles/12304248-managing-api-key-environment-variables-in-claude-code)

**Authentication Hierarchy:**

1. **ANTHROPIC_API_KEY (Recommended for Production)**
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-api03-...
   ```
   - Pay-per-use billing
   - Headless compatible
   - No browser OAuth required
   - Works in containers

2. **Subscription (Claude Pro/Max) - NOT for containers**
   - Requires browser login (`claude auth login`)
   - OAuth flow with callback
   - Not suitable for headless servers
   - Container deployment issues

3. **Long-lived Access Tokens (Alternative)**
   ```bash
   claude setup-token
   export CLAUDE_CODE_OAUTH_TOKEN=<token>
   ```
   - Works in containers
   - Linked to subscription
   - Can be mounted as secret

**Docker Volume Mounting (Alternative to Environment Variables):**

> "For Docker containers, you can mount the credential file as a read-only volume using `docker run -v ~/.config/claude-code/auth.json:/root/.config/claude-code/auth.json:ro -it my-dev-image`." - [Claude Code Docker Complete Guide](https://smartscope.blog/en/generative-ai/claude/claude-code-docker-guide/)

**Recommended Production Pattern:**

```dockerfile
FROM python:3.12-slim

RUN curl -fsSL https://claude.ai/install.sh | bash
RUN pip install claude-agent-sdk

ENV ANTHROPIC_API_KEY=""

CMD ["python", "app.py"]
```

```bash
docker run -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY myapp
```

#### Headless Authentication Issues (2025 Status)

**Known Issues:**

> "There are known issues with headless mode authentication: Any time I attempt to run claude via claude -p 'test' it returns Invalid API key · Fix external API key. In a non-interactive environment, the CLI still requires executing /login even though an API key is provided." - [GitHub Issue #5666](https://github.com/anthropics/claude-code/issues/5666)

**Workaround:**

The Claude Agent SDK handles authentication better than raw CLI calls. Use the SDK instead of direct `claude -p` commands:

```python

from claude_agent_sdk import query, ClaudeAgentOptions
import os

os.environ["ANTHROPIC_API_KEY"] = "your-key"

async for message in query(
    prompt="test",
    options=ClaudeAgentOptions(setting_sources=None)
):
    print(message)
```

**Verification:**

> "Run /status in Claude Code periodically to verify your current authentication method. To verify if an API key is set as an environment variable, run /status in Claude Code." - [Managing API Key Environment Variables](https://support.claude.com/en/articles/12304248-managing-api-key-environment-variables-in-claude-code)

#### Cost Comparison: Subscription vs API

**Claude Max Subscription:**
- $100/month → 5x usage of Pro
- $200/month → 20x usage of Pro (Opus 4.5 access)

**Anthropic API:**
- Claude Opus 4.5: $5.00/M input tokens, $25.00/M output tokens
- Claude Sonnet 4.5: $3.00/M input, $15.00/M output (≤200K context)
- Claude Sonnet 4.5: $6.00/M input, $22.50/M output (>200K context)

**Value Analysis:**

> "If you max out the $100 Max plan, that's approximately $7,400 worth of API usage equivalent, 74x the amount you pay. You can get $150 worth of API usage for the price of $20 a month with a Claude Pro subscription." - [LLM Subscriptions vs APIs Value](https://www.asad.pw/llm-subscriptions-vs-apis-value-for-money/)

**Recommendation:**

> "API is best for production deployments, automated pipelines, backends, or when you want to control exact spend. The API removes per-seat fees and allows unlimited developers behind a single deployment, but you pay per token." - [Claude Code Usage Limits and Subscription Plans](https://www.geeky-gadgets.com/claude-code-usage-limits-pricing-plans-guide-sept-2025/)

**When to Use Each:**

| Scenario | Recommendation | Reason |
|----------|----------------|--------|
| Development | Claude Max Subscription | Predictable costs, generous limits |
| CI/CD Automation | Anthropic API | Headless compatible |
| Production Backend | Anthropic API | Pay-per-use, scales with traffic |
| Multiple Developers | Anthropic API | No per-seat fees |
| High-volume | Anthropic API | Better cost control |
| Prototype/MVP | Claude Max Subscription | Faster setup |

---

## 5. Complete Architecture Pattern

### End-to-End Flow

```
┌─────────────┐
│   React     │
│   Frontend  │
└──────┬──────┘
       │ 1. User clicks button
       │
       ▼
┌─────────────────────────────────────┐
│         FastAPI Backend             │
│  ┌──────────────────────────────┐   │
│  │ 2. Load context from         │   │
│  │    PostgreSQL                │   │
│  │                              │   │
│  │ user_data = await db.query() │   │
│  └──────────────────────────────┘   │
│                                     │
│  ┌──────────────────────────────┐   │
│  │ 3. Call Claude Agent SDK     │   │
│  │                              │   │
│  │ async for msg in query(      │   │
│  │   prompt=prompt,             │   │
│  │   options={                  │   │
│  │     mcp_servers={            │   │
│  │       "postgres": {...}      │   │
│  │     }                        │   │
│  │   }                          │   │
│  │ )                            │   │
│  └──────────────────────────────┘   │
└──────────┬──────────────────────────┘
           │
           ▼
┌─────────────────────────┐
│  Claude Agent SDK       │
│  (Python Library)       │
└──────────┬──────────────┘
           │ 4. Spawns subprocess
           │
           ▼
┌─────────────────────────┐
│  Claude Code CLI        │
│  (claude binary)        │
└──────────┬──────────────┘
           │ 5. API request
           │
           ▼
┌─────────────────────────┐
│  Anthropic API          │
│  (Claude Opus/Sonnet)   │
└──────────┬──────────────┘
           │
           │ 6. Needs data
           │
           ▼
┌─────────────────────────┐
│  MCP Server             │
│  (Database Proxy)       │
└──────────┬──────────────┘
           │ 7. SQL query
           │
           ▼
┌─────────────────────────┐
│  PostgreSQL Database    │
└─────────────────────────┘
```

### Complete Implementation Example

```python

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from claude_agent_sdk import query, ClaudeAgentOptions
import os
import json

app = FastAPI()

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class GenerateRequest(BaseModel):
    user_id: int
    prompt: str

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

@app.post("/api/generate-email")
async def generate_email(request: GenerateRequest):
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.id == request.user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        context = f"""
        User Profile:
        - Name: {user.name}
        - Email: {user.email}
        - Join Date: {user.created_at}
        - Total Orders: {len(user.orders)}
        - Preferences: {user.preferences}
        """

        full_prompt = f"{context}\n\n{request.prompt}"

        async def stream_response():
            async for message in query(
                prompt=full_prompt,
                options=ClaudeAgentOptions(
                    allowed_tools=[],
                    permission_mode="bypassPermissions",
                    mcp_servers={
                        "postgres": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-postgres"],
                            "env": {
                                "POSTGRES_URL": DATABASE_URL
                            }
                        }
                    }
                )
            ):
                if hasattr(message, 'content'):
                    yield json.dumps({"content": message.content}) + "\n"

        return StreamingResponse(stream_response(), media_type="application/x-ndjson")

@app.post("/api/analyze-database")
async def analyze_database(query_prompt: str):
    async def stream_response():
        async for message in query(
            prompt=f"Using the postgres MCP server, {query_prompt}",
            options=ClaudeAgentOptions(
                mcp_servers={
                    "postgres": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-postgres"],
                        "env": {
                            "POSTGRES_URL": os.getenv("DATABASE_URL")
                        }
                    }
                }
            )
        ):
            if hasattr(message, 'content'):
                yield json.dumps({"data": message.content}) + "\n"

    return StreamingResponse(stream_response(), media_type="application/x-ndjson")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### React Frontend Integration

```typescript

import { useState } from 'react';

export function EmailGenerator() {
  const [loading, setLoading] = useState(false);
  const [content, setContent] = useState('');

  const handleGenerate = async () => {
    setLoading(true);
    setContent('');

    const response = await fetch('/api/generate-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: 123,
        prompt: 'Write a personalized welcome email'
      })
    });

    const reader = response.body?.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader!.read();
      if (done) break;

      const chunk = decoder.decode(value);
      const lines = chunk.split('\n').filter(Boolean);

      for (const line of lines) {
        const data = JSON.parse(line);
        setContent(prev => prev + data.content);
      }
    }

    setLoading(false);
  };

  return (
    <div>
      <button onClick={handleGenerate} disabled={loading}>
        {loading ? 'Generating...' : 'Generate Email'}
      </button>
      <div>{content}</div>
    </div>
  );
}
```

### Docker Compose Setup

```yaml

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: myapp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  backend:
    build: ./backend
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - DATABASE_URL=postgresql+asyncpg://postgres:${POSTGRES_PASSWORD}@postgres:5432/myapp
    depends_on:
      - postgres
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app

  frontend:
    build: ./frontend
    environment:
      - VITE_API_URL=http://localhost:8000
    ports:
      - "5173:5173"
    volumes:
      - ./frontend:/app

volumes:
  postgres_data:
```

### Backend Dockerfile

```dockerfile

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y curl nodejs npm git && \
    curl -fsSL https://claude.ai/install.sh | bash && \
    apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

---

## Key Takeaways

### 1. Use the Claude Agent SDK (Not Raw CLI)

The SDK provides production-ready abstractions over subprocess management, authentication, streaming, and error handling. It's the recommended approach for FastAPI backends.

### 2. MCP Servers Are Optional But Powerful

For simple prompts with small context, pass data directly in the prompt. For repeated database access or large datasets, configure MCP servers within the SDK options.

### 3. MCP Servers Are NOT Mounted on FastAPI

You don't use `app.mount("/mcp", mcp)` for this use case. MCP servers are configured in the `ClaudeAgentOptions` and run as separate processes that Claude Code connects to.

### 4. Use API Key Authentication for Production

Set `ANTHROPIC_API_KEY` environment variable. Subscription-based authentication (Claude Pro/Max) requires browser OAuth and doesn't work well in containerized headless environments.

### 5. API Billing Is Better for Production

Pay-per-use API billing scales better than subscriptions for production backends. It removes per-seat fees and provides precise cost control.

### 6. Streaming Is Important for UX

Implement streaming responses to show progress to users. The SDK supports async streaming out of the box.

### 7. Session Management Enables Context

Use session IDs to maintain conversation context across multiple requests. This enables multi-turn interactions.

---

## Sources and References

### Official Documentation
- [Claude Agent SDK Overview](https://platform.claude.com/docs/en/api/agent-sdk/overview) - Official SDK documentation
- [Claude Code CLI Reference](https://code.claude.com/docs/en/cli-reference) - CLI flags and programmatic usage
- [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp) - MCP server configuration
- [Managing API Key Environment Variables](https://support.claude.com/en/articles/12304248-managing-api-key-environment-variables-in-claude-code) - Authentication methods
- [Using Claude Code with your Pro or Max plan](https://support.claude.com/en/articles/11145838-using-claude-code-with-your-pro-or-max-plan) - Subscription integration

### Technical Guides
- [Claude Code Best Practices](https://www.anthropic.com/engineering/claude-code-best-practices) - Official best practices for agentic coding
- [Building Agents with the Claude Agent SDK](https://www.anthropic.com/engineering/building-agents-with-the-claude-agent-sdk) - Agent development patterns
- [Introducing the Model Context Protocol](https://www.anthropic.com/news/model-context-protocol) - MCP standard explanation

### Integration Examples
- [claude-code-fastapi by e2b-dev](https://github.com/e2b-dev/claude-code-fastapi) - FastAPI wrapper for Claude Code with E2B sandboxes
- [claude-code-api by codingworkflow](https://github.com/codingworkflow/claude-code-api) - OpenAI-compatible API gateway
- [fastapi-nextjs-docker-github-actions-reference](https://github.com/raveenb/fastapi-nextjs-docker-github-actions-reference) - Full-stack reference with CI/CD

### MCP Resources
- [FastAPI-MCP by tadata-org](https://github.com/tadata-org/fastapi_mcp) - Expose FastAPI endpoints as MCP tools
- [How to Use FastAPI MCP Server](https://huggingface.co/blog/lynn-mikami/fastapi-mcp-server) - Integration guide
- [Model Context Protocol Servers](https://github.com/modelcontextprotocol/servers) - Official MCP server implementations

### Cost and Deployment
- [Claude Pricing Explained](https://intuitionlabs.ai/articles/claude-pricing-plans-api-costs) - Subscription vs API comparison
- [LLM Subscriptions vs APIs Value](https://www.asad.pw/llm-subscriptions-vs-apis-value-for-money/) - Cost analysis
- [Claude Code Docker Complete Guide](https://smartscope.blog/en/generative-ai/claude/claude-code-docker-guide/) - Containerization patterns
- [Configure Claude Code | Docker Docs](https://docs.docker.com/ai/sandboxes/claude-code/) - Official Docker integration

### Community Resources
- [Claude Code Python SDK Guide](https://adrianomelo.com/posts/claude-code-python-sdk.html) - SDK architecture explanation
- [A Practical Guide to the Python Claude Code SDK](https://www.eesel.ai/blog/python-claude-code-sdk) - 2025 SDK guide
- [Optimising MCP Server Context Usage](https://scottspence.com/posts/optimising-mcp-server-context-usage-in-claude-code) - Token optimization
- [Claude Code as an MCP Server](https://www.ksred.com/claude-code-as-an-mcp-server-an-interesting-capability-worth-understanding/) - Dual role explanation

### GitHub Issues
- [Issue #5666: Invalid API Key in headless mode](https://github.com/anthropics/claude-code/issues/5666) - Authentication challenges
- [Issue #7100: Document Headless/Remote Authentication](https://github.com/anthropics/claude-code/issues/7100) - CI/CD authentication
- [Issue #1736: Re-authenticating in Docker container](https://github.com/anthropics/claude-code/issues/1736) - Container deployment

---

**Research Completed:** 2025-12-14
**Last Updated:** 2025-12-14
**Status:** Comprehensive - Ready for implementation
