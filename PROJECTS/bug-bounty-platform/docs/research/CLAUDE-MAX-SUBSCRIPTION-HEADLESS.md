# Claude Max Subscription Programmatic Access Research

**Research Date:** 2025-12-14
**Focus:** Using Claude Max ($200/month) subscription programmatically in headless FastAPI backend environments
**Critical Question:** Can we use Max subscription instead of paying additional API costs?

---

## Executive Summary

**ANSWER: YES, BUT WITH SIGNIFICANT CAVEATS**

Claude Max subscriptions CAN be used programmatically in headless environments through Claude Code's OAuth authentication system. However, this approach exists in a **policy gray area** and has several production limitations:

### Key Findings:
1. **Technical Feasibility:** ✅ Possible via `CLAUDE_CODE_OAUTH_TOKEN` environment variable
2. **Official Support:** ⚠️ Limited - designed for interactive use, headless support is undocumented
3. **Terms of Service:** ⚠️ Unclear if automated usage violates ToS for consumer subscriptions
4. **Production Viability:** ⚠️ OAuth tokens expire (8-12 hours), requiring refresh mechanisms
5. **Cost Savings:** ✅ Significant - Max subscription vs. per-token API pricing

---

## Solution Summary

Claude Max subscriptions provide programmatic access through **Claude Code** using OAuth 2.0 authentication. You can authenticate in headless environments by:

1. Running `claude setup-token` to generate long-lived OAuth tokens
2. Injecting tokens via `CLAUDE_CODE_OAUTH_TOKEN` environment variable in Docker containers
3. Mounting `~/.claude/.credentials.json` as a volume for persistent authentication
4. Using the unofficial `claude_max` Python package that wraps this authentication

**However:** This approach is NOT officially documented for production server use and may violate consumer subscription terms of service. Anthropic's official position is that API usage should use the separate Anthropic API with commercial terms.

---

## Detailed Analysis

### 1. Authentication Methods for Headless Environments

#### Option A: OAuth Token Environment Variable

**How it works:**
```bash
# Generate token interactively
claude setup-token

# Export token for headless use
export CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-your-token-here"

# Run Claude Code programmatically
claude status
```

**Token Format:**
- Access tokens: `sk-ant-oat01-...` (expires in 8-12 hours)
- Refresh tokens: `sk-ant-ort01-...` (longer-lived, but also expires)

**Docker Usage:**
```bash
docker run --rm -it \
  -e CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-..." \
  -v $(pwd):/app \
  your-fastapi-image
```

**Sources:**
- [Setup Container Authentication - Claude Did This](https://claude-did-this.com/claude-hub/getting-started/setup-container-guide)
- [GitHub Issue #7100 - Headless Authentication Documentation](https://github.com/anthropics/claude-code/issues/7100)
- [Claude Code SDK Docker Repository](https://github.com/cabinlab/claude-code-sdk-docker)

---

#### Option B: Mount Authentication Credentials Volume

**Directory Structure:**
```
~/.claude/
├── .credentials.json      # OAuth tokens (access + refresh)
├── settings.local.json    # User preferences
└── [project data]
```

**Docker Compose Example:**
```yaml
services:
  fastapi:
    image: your-fastapi-image
    volumes:
      - ~/.claude:/root/.claude:ro  # Mount read-only for security
      - ./app:/app
```

**Advantages:**
- Automatic token refresh handled by Claude Code
- No need to manually extract tokens
- More secure than environment variables

**Disadvantages:**
- Requires initial interactive authentication
- Credentials tied to host machine
- Not suitable for cloud deployments without pre-setup

**Sources:**
- [Docker Docs - Configure Claude Code](https://docs.docker.com/ai/sandboxes/claude-code/)
- [GitHub Issue #1736 - Avoiding Re-authentication](https://github.com/anthropics/claude-code/issues/1736)
- [Medium - Running Claude Code in Docker Containers](https://medium.com/rigel-computer-com/running-claude-code-in-docker-containers-one-project-one-container-1601042bf49c)

---

#### Option C: claude_max Python Package

**What it is:**
An unofficial Python package published to PyPI (June 15, 2025) that programmatically accesses Claude Code's authentication system to use Max subscriptions for API-style completions.

**How it works:**
- Implements OAuth 2.0 with PKCE security
- Extracts authentication from Claude Code
- Provides API-compatible interface using subscription credits

**Usage Pattern:**
```python
from claude_max import ClaudeMax

# Initialize with Max subscription credentials
client = ClaudeMax()

# Make API-style calls using subscription
response = client.complete(
    model="claude-opus-4-5",
    messages=[{"role": "user", "content": "Hello"}]
)
```

**Critical Warning:**
> "Claude Max subscribers pay $200/month, yet there's no official way to use subscriptions for automation, with the only workaround involving fragile OAuth token extraction that may violate ToS."

**Sources:**
- [How I Built claude_max - Substack Article](https://idsc2025.substack.com/p/how-i-built-claude_max-to-unlock)
- [Maximizing Claude Max Subscription - Deeplearning.fr](https://deeplearning.fr/maximizing-your-claude-max-subscription-complete-guide-to-automated-workflows-with-claude-code-and-windsurf/)

---

### 2. Mobile Apps and Browser Wrappers Authentication

**Research Question:** How do mobile Claude apps use Max subscription if not through API?

**Finding:** Mobile apps and browser extensions use the **same OAuth 2.0 flow** as Claude Code:

1. User logs in with claude.ai credentials
2. OAuth authorization flow with PKCE
3. Receives access token (`sk-ant-oat01-...`) and refresh token (`sk-ant-ort01-...`)
4. Stores tokens locally for subsequent requests
5. Automatically refreshes when access token expires

**Key Insight:**
Mobile apps are **consumer-facing interactive applications**, which aligns with the Max subscription terms of service. A headless FastAPI backend is a **server-to-server automation**, which may NOT align with consumer subscription terms.

**Authentication Endpoint:**
```
POST https://console.anthropic.com/v1/oauth/token
{
  "grant_type": "refresh_token",
  "refresh_token": "sk-ant-ort01-...",
  "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
}
```

**Sources:**
- [Claude Code Provider - Roo Code Documentation](https://docs.roocode.com/providers/claude-code)
- [GitHub - claude-token-refresh Tool](https://github.com/RavenStorm-bit/claude-token-refresh)
- [Unlock Claude API from Claude Pro/Max](https://www.alif.web.id/posts/claude-oauth-api-key)

---

### 3. Long-Lived Access Tokens from Claude Max

#### Token Lifespan

| Token Type | Prefix | Lifespan | Purpose |
|------------|--------|----------|---------|
| Access Token | `sk-ant-oat01-...` | 8-12 hours | Authenticate API requests |
| Refresh Token | `sk-ant-ort01-...` | Days to weeks | Obtain new access tokens |
| API Key | `sk-ant-api03-...` | Indefinite | Anthropic API (separate billing) |

#### `claude setup-token` Command

**Purpose:** Generate long-lived OAuth tokens for headless/CI/CD environments

**Usage:**
```bash
# Interactive setup
claude setup-token

# Output:
# "Your OAuth token: sk-ant-oat01-ABCxyz..."
# "Save this token securely - it provides full access to your account"

# Use in environment
export CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-ABCxyz..."
```

**Known Issues:**
- Tokens still expire after 8-12 hours
- No official documentation for production use
- Refresh token handling required for long-running services

**Bug Reports:**
> "OAuth tokens expire during long-running autonomous tasks, causing 401 authentication_error failures that require manual /login intervention."

**Sources:**
- [GitHub Issue #8938 - setup-token Not Enough to Authenticate](https://github.com/anthropics/claude-code/issues/8938)
- [GitHub Issue #12447 - OAuth Token Expiration Disrupts Workflows](https://github.com/anthropics/claude-code/issues/12447)
- [Elixir Mix Task Documentation](https://hexdocs.pm/claude_agent_sdk/Mix.Tasks.Claude.SetupToken.html)

---

### 4. Subscription Usage vs API Usage

#### How to Verify You're Using Subscription (Not API)

**Method 1: `/status` Command**
```bash
claude status

# Expected output for subscription:
# Authentication: Claude Max Subscription
# Usage: 45 of 900 messages remaining (resets in 3h 22m)
# Cost: Included in subscription

# Expected output for API:
# Authentication: API Key
# Usage: $12.45 this month
# Cost: Pay-per-token
```

**Method 2: Check Environment Variables**
```bash
# Priority order (first found wins):
# 1. ANTHROPIC_API_KEY → Uses API (costs money)
# 2. CLAUDE_CODE_OAUTH_TOKEN → Uses subscription
# 3. ~/.claude/.credentials.json → Uses subscription

# Ensure API key is NOT set:
echo $ANTHROPIC_API_KEY
# Should be empty for subscription use
```

**Method 3: Check Billing Dashboard**

Subscription usage shows as:
- **$0.00 per request** in API console
- Messages count against 5-hour rolling window
- No per-token charges

API usage shows as:
- **$X.XX per request** based on token count
- Cumulative monthly charges
- Detailed token breakdown

**Rate Limits Comparison:**

| Plan | Messages (5hr) | Prompts (5hr) | Weekly Capacity |
|------|---------------|---------------|-----------------|
| Max 5x ($100) | ~225 | 50-200 | 140-280hr Sonnet / 15-35hr Opus |
| Max 20x ($200) | ~900 | 200-800 | 240-480hr Sonnet / 24-40hr Opus |
| API | Unlimited* | Unlimited* | Based on tier/spending |

*API has separate rate limits based on tier

**Important Note:**
> "Both Pro and Max plans offer usage limits that are shared across Claude and Claude Code, meaning all activity in both tools counts against the same usage limits."

**Sources:**
- [Using Claude Code with Pro or Max Plan - Claude Help](https://support.claude.com/en/articles/11145838-using-claude-code-with-your-pro-or-max-plan)
- [About Claude's Max Plan Usage - Claude Help](https://support.claude.com/en/articles/11014257-about-claude-s-max-plan-usage)
- [GitHub Issue #1721 - Need Usage Gauge](https://github.com/anthropics/claude-code/issues/1721)
- [GitHub Issue #1287 - Misleading Cost Command Output](https://github.com/anthropics/claude-code/issues/1287)

---

### 5. Terms of Service and Policy Analysis

#### Official Anthropic Position

**Subscription vs. API Separation:**
> "A paid Claude subscription enhances your chat experience but doesn't include access to the Claude API or Console, requiring separate sign-up for API usage."

**Consumer vs. Commercial Terms:**
> "The consumer terms updates apply to users on Claude Free, Pro, and Max plans (including when they use Claude Code), but they do not apply to services under Commercial Terms, including API use."

**Key Implication:**
Max subscriptions fall under **consumer terms**, which are designed for interactive human use. Headless server automation may be considered outside the intended use case.

#### Policy Gray Area

**The Problem:**
- Claude Code technically supports headless mode
- `CLAUDE_CODE_OAUTH_TOKEN` exists for automation
- But terms of service don't explicitly permit automated usage for consumer subscriptions

**Community Concern:**
> "Claude Max subscribers pay $200/month, yet there's no official way to use subscriptions for automation... it's unclear if token extraction workarounds violate ToS. This situation undermines the value proposition of Claude Max for developers who want to integrate Claude Code into workflows."

**Feature Request (GitHub Issue #1454):**
Title: "Feature Request: Machine to Machine Authentication for Claude Max Subscriptions"

Status: Open (no official response confirming or denying legitimacy)

#### Risk Assessment for Production Use

| Risk Factor | Level | Mitigation |
|-------------|-------|------------|
| Account suspension | Medium | Use for personal projects, not enterprise |
| Token expiration | High | Implement refresh token logic |
| Policy changes | Medium | Monitor Anthropic announcements |
| Lack of support | High | No SLA for subscription-based automation |
| ToS violation | Unknown | Consult legal/Anthropic directly |

**Recommended Approach:**
1. **For personal/development:** Use Max subscription with awareness of limitations
2. **For production/enterprise:** Use official Anthropic API with commercial terms
3. **For cost optimization:** Evaluate if Max subscription ($200/month) covers your usage vs. API costs

**Sources:**
- [Feature Request #1454 - Machine to Machine Auth](https://github.com/anthropics/claude-code/issues/1454)
- [Why Pay Separately for API - Claude Help](https://support.anthropic.com/en/articles/9876003-i-have-a-paid-claude-subscription-pro-max-team-or-enterprise-plans-why-do-i-have-to-pay-separately-to-use-the-claude-api-and-console)
- [Updates to Consumer Terms - Anthropic News](https://www.anthropic.com/news/updates-to-our-consumer-terms)
- [Claude vs Claude API vs Claude Code - 16x Engineer](https://eval.16x.engineer/blog/claude-vs-claude-api-vs-claude-code)

---

## Alternative Approaches (If Subscription Headless Doesn't Work)

### Option 1: Hybrid Architecture

**Design:**
- FastAPI backend uses official Anthropic API for production
- Claude Code (Max subscription) used for development/testing only
- Separate billing but predictable costs

**Cost Structure:**
- Development: $200/month Max subscription
- Production: Pay-per-token API (budget based on usage)

---

### Option 2: WebSocket Proxy to Local Claude Code

**Architecture:**
```
FastAPI Backend (Server)
    ↓ WebSocket Connection
Local Claude Code Instance (Developer Machine)
    ↓ OAuth Authentication
Claude Max Subscription
```

**Advantages:**
- Definitely uses Max subscription
- No ToS concerns (interactive use)

**Disadvantages:**
- Not suitable for production deployment
- Requires developer machine always running
- Single point of failure

---

### Option 3: Official Enterprise Plan

**What it is:**
Enterprise plans may have different terms allowing automated usage.

**Next Steps:**
Contact Anthropic sales to inquire about:
- Enterprise API access using subscription model
- Custom rate limits
- Commercial terms for automated workflows

**Sources:**
- [Claude Pricing - Anthropic](https://claude.com/pricing)

---

## Production Implementation Guide

### If Proceeding with Max Subscription Headless (Despite Risks)

#### Step 1: Generate OAuth Tokens

```bash
# On development machine
claude setup-token

# Save output securely
# Access token: sk-ant-oat01-...
# Refresh token: sk-ant-ort01-... (from ~/.claude/.credentials.json)
```

#### Step 2: Docker Container Setup

**Dockerfile:**
```dockerfile
FROM python:3.12-slim

# Install Claude Code
RUN pip install claude-code

# Copy application
COPY ./app /app
WORKDIR /app

# Environment variable will be injected at runtime
ENV CLAUDE_CODE_OAUTH_TOKEN=""

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  fastapi:
    build: .
    environment:
      # CRITICAL: Do NOT set ANTHROPIC_API_KEY
      # It takes precedence over OAuth token
      CLAUDE_CODE_OAUTH_TOKEN: ${CLAUDE_CODE_OAUTH_TOKEN}
    volumes:
      - ./app:/app
    ports:
      - "8000:8000"

secrets:
  claude_oauth_token:
    file: ./secrets/claude_oauth_token.txt
```

#### Step 3: Token Refresh Mechanism

**Python Implementation:**
```python
import httpx
import json
from pathlib import Path

class ClaudeMaxAuth:
    def __init__(self):
        self.credentials_path = Path.home() / ".claude" / ".credentials.json"
        self.access_token = None
        self.refresh_token = None
        self._load_credentials()

    def _load_credentials(self):
        """Load tokens from credentials file or environment"""
        if self.credentials_path.exists():
            with open(self.credentials_path) as f:
                creds = json.load(f)
                oauth = creds.get("claudeAiOauth", {})
                self.access_token = oauth.get("accessToken")
                self.refresh_token = oauth.get("refreshToken")

    async def refresh_access_token(self):
        """Refresh expired access token"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://console.anthropic.com/v1/oauth/token",
                json={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                    "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
                }
            )
            response.raise_for_status()
            data = response.json()
            self.access_token = data["access_token"]
            # Update credentials file
            self._save_credentials()

    def _save_credentials(self):
        """Save updated tokens back to credentials file"""
        # Implementation details...
        pass
```

**Usage in FastAPI:**
```python
from fastapi import FastAPI, Depends
from claude_max import ClaudeMaxAuth

app = FastAPI()
auth = ClaudeMaxAuth()

async def get_claude_client():
    """Dependency that ensures fresh tokens"""
    # Check if token needs refresh (implement logic)
    if auth.token_expired():
        await auth.refresh_access_token()
    return auth

@app.post("/api/chat")
async def chat(
    request: ChatRequest,
    claude: ClaudeMaxAuth = Depends(get_claude_client)
):
    # Use claude.access_token for requests
    pass
```

#### Step 4: Monitoring and Fallback

**Monitor subscription usage:**
```python
import subprocess

def check_subscription_status():
    """Check Claude Code subscription status"""
    result = subprocess.run(
        ["claude", "status"],
        capture_output=True,
        text=True
    )
    # Parse output to check remaining quota
    return result.stdout
```

**Implement fallback to API:**
```python
async def make_claude_request(prompt: str):
    """Try subscription first, fallback to API"""
    try:
        # Try subscription
        response = await request_via_subscription(prompt)
        return response
    except QuotaExceededError:
        # Fallback to API
        logging.warning("Subscription quota exceeded, using API")
        return await request_via_api(prompt)
```

---

## Critical Production Considerations

### 1. Token Expiration Handling

**Problem:**
Access tokens expire every 8-12 hours, causing service interruptions.

**Solutions:**
- Implement automatic refresh before expiration
- Use refresh token rotation
- Monitor token validity and proactively refresh
- Have API key fallback for emergencies

### 2. Rate Limit Management

**Max Subscription Limits:**
- 900 messages / 5 hours (Max 20x plan)
- 200-800 prompts / 5 hours for Claude Code

**Strategies:**
- Implement request queuing
- Track usage against 5-hour rolling window
- Return 429 errors when approaching limit
- Cache responses to reduce requests

### 3. Shared Quota Between Web and Code

**Critical Issue:**
> "Usage limits are shared between Claude Code and web claude.ai usage"

**Implications:**
- If you use claude.ai in browser, it reduces FastAPI quota
- No way to reserve capacity for backend only
- Unpredictable availability during high web usage

**Mitigation:**
- Use separate Claude account for backend
- Monitor total usage across all channels
- Set up alerts for high usage

### 4. No Service Level Agreement (SLA)

**Risk:**
- No guaranteed uptime for subscription-based access
- No support for programmatic usage issues
- Changes can break implementation without notice

**Mitigation:**
- Don't use for mission-critical services
- Always have API fallback
- Monitor Anthropic announcements

---

## Cost-Benefit Analysis

### Scenario 1: Light Usage (< $200/month API cost)

**Recommendation:** Use Anthropic API directly

**Reasoning:**
- Simpler implementation
- Official support
- Commercial terms
- Predictable costs

### Scenario 2: Heavy Usage ($200-$1000/month API cost)

**Recommendation:** Max subscription for development, API for production

**Reasoning:**
- Max subscription saves development costs
- API provides production reliability
- Total cost still lower than pure API
- Clear separation of concerns

### Scenario 3: Very Heavy Usage (> $1000/month API cost)

**Recommendation:** Contact Anthropic for Enterprise plan

**Reasoning:**
- Custom pricing available
- Potentially subscription-style billing for automation
- Dedicated support
- SLA guarantees

---

## Final Recommendations

### ✅ Use Max Subscription Headless If:
- Personal project or internal tool
- Comfortable with policy gray area
- Can handle occasional service disruptions
- Have technical ability to implement token refresh
- Usage fits within Max limits ($200/month tier)

### ❌ Do NOT Use Max Subscription Headless If:
- Production customer-facing service
- Enterprise/commercial application
- Need SLA guarantees
- Usage exceeds Max limits
- Uncomfortable with potential ToS violations

### ✅ Recommended Approach:
1. **Development:** Use Max subscription ($200/month)
2. **Staging:** Use Max subscription with monitoring
3. **Production:** Use official Anthropic API with commercial terms
4. **Cost Optimization:** Evaluate usage patterns after 1 month

---

## Authoritative Sources Summary

### Official Documentation:
- [Using Claude Code with Pro or Max - Claude Help](https://support.claude.com/en/articles/11145838-using-claude-code-with-your-pro-or-max-plan)
- [Docker Configure Claude Code](https://docs.docker.com/ai/sandboxes/claude-code/)
- [Claude Code Development Containers](https://code.claude.com/docs/en/devcontainer)

### Community Resources:
- [GitHub - claude-code-sdk-docker](https://github.com/cabinlab/claude-code-sdk-docker)
- [Setup Container Authentication Guide](https://claude-did-this.com/claude-hub/getting-started/setup-container-guide)
- [GitHub - claude-token-refresh Tool](https://github.com/RavenStorm-bit/claude-token-refresh)

### Technical Analysis:
- [How I Built claude_max - Substack](https://idsc2025.substack.com/p/how-i-built-claude_max-to-unlock)
- [Claude vs Claude API vs Claude Code](https://eval.16x.engineer/blog/claude-vs-claude-api-vs-claude-code)

### GitHub Issues (Feature Requests & Bugs):
- [Issue #1454 - Machine to Machine Auth for Max](https://github.com/anthropics/claude-code/issues/1454)
- [Issue #7100 - Document Headless Authentication](https://github.com/anthropics/claude-code/issues/7100)
- [Issue #12447 - OAuth Token Expiration](https://github.com/anthropics/claude-code/issues/12447)
- [Issue #8938 - setup-token Not Enough](https://github.com/anthropics/claude-code/issues/8938)

---

## Open Questions (Require Official Anthropic Response)

1. **Is programmatic use of Max subscriptions permitted under consumer ToS?**
   - Status: Unclear
   - Action: Submit support ticket to Anthropic

2. **Will Max subscriptions ever support official headless/server authentication?**
   - Status: Feature request open (Issue #1454)
   - Action: Monitor GitHub issues

3. **What is the intended use case for `claude setup-token` command?**
   - Status: Undocumented
   - Action: Request official documentation

4. **Are there Enterprise plans with subscription-style pricing for automation?**
   - Status: Unknown
   - Action: Contact Anthropic sales

---

## Conclusion

**YES, you CAN use Claude Max subscription programmatically in headless FastAPI backends** through OAuth token authentication, but this approach:

1. ✅ **Works technically** - Multiple methods available
2. ⚠️ **Exists in policy gray area** - ToS unclear on automated usage
3. ⚠️ **Requires token refresh implementation** - Not zero-maintenance
4. ⚠️ **Has production limitations** - No SLA, shared quotas, expiring tokens
5. ✅ **Saves significant costs** - $200/month vs potentially thousands in API fees

**Recommended path forward:**
1. Prototype with Max subscription to prove concept
2. Measure actual usage patterns
3. Calculate API costs for production scale
4. **If costs < $200/month:** Switch to official API
5. **If costs > $200/month:** Continue with Max but implement robust fallback
6. **If costs >> $1000/month:** Contact Anthropic for Enterprise pricing

**Critical action item:** Submit support ticket to Anthropic asking explicitly if programmatic use of Max subscriptions for headless server environments is permitted under current ToS.

---

**Research Completed:** 2025-12-14
**Last Updated:** 2025-12-14
**Next Review:** Monitor GitHub issues and Anthropic announcements monthly
