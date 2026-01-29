# Security Features Explained

This document explains the security features implemented in the Bug Bounty Platform, the threats they mitigate, and best practices for secure development.

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Authentication](#authentication)
3. [Authorization](#authorization)
4. [Password Security](#password-security)
5. [Token Security](#token-security)
6. [Input Validation](#input-validation)
7. [Rate Limiting](#rate-limiting)
8. [Common Vulnerabilities Prevented](#common-vulnerabilities-prevented)
9. [Security Best Practices](#security-best-practices)

---

## Security Overview

Security is implemented in **multiple layers**:

```
┌──────────────────────────────────────────────────────────┐
│  Layer 1: Input Validation (Pydantic)                    │
│  - Type checking                                          │
│  - String length limits                                   │
│  - Email/URL format validation                            │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  Layer 2: Authentication (JWT)                            │
│  - Token-based auth                                       │
│  - Short-lived access tokens (15 min)                     │
│  - Token rotation                                         │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  Layer 3: Authorization (RBAC)                            │
│  - Role-based access control                              │
│  - Resource ownership checks                              │
│  - Admin-only endpoints                                   │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  Layer 4: Rate Limiting                                   │
│  - 100 req/min default                                    │
│  - 20 req/min for auth endpoints                          │
│  - Per-IP tracking                                        │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  Layer 5: Secure Storage                                  │
│  - Argon2id password hashing                              │
│  - Hashed refresh tokens                                  │
│  - No plaintext secrets                                   │
└──────────────────────────────────────────────────────────┘
```

**Defense in Depth:** If one layer fails, others still protect.

---

## Authentication

### JWT Token-Based Authentication

**Why JWT?**
- Stateless (no session storage on server)
- Scalable (works across multiple servers)
- Contains user info (no database lookup on every request)

**Token Structure:**

```json
{
  "sub": "018d3f54-8c3a-7000-a234-56789abcdef0",  // user_id
  "role": "user",
  "token_version": 1,
  "exp": 1704123456,  // expires in 15 minutes
  "iat": 1704122556   // issued at
}
```

**Header:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Two-Token System

**Access Token:**
- Short-lived (15 minutes)
- Sent with every API request
- Cannot be revoked (stateless)
- If stolen, attacker only has 15 minutes

**Refresh Token:**
- Long-lived (7 days)
- Used only to get new access token
- Stored in database (can be revoked)
- Single-use (rotated on refresh)

**Why two tokens?**
- Compromise: Security vs UX
- Access token: Fast (no DB lookup), but can't revoke
- Refresh token: Slow (DB lookup), but can revoke

### Login Flow

```
┌──────────────────────────────────────────────────────────┐
│  1. User submits email + password                         │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  2. Verify password (Argon2id)                            │
│     - Timing-safe comparison                              │
│     - No early returns                                    │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  3. Generate access token (JWT)                           │
│     - Signed with SECRET_KEY                              │
│     - Expires in 15 minutes                               │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  4. Generate refresh token                                │
│     - Random 32-byte string                               │
│     - SHA-256 hash stored in DB                           │
│     - Original token sent to client                       │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  5. Return both tokens                                    │
│     { access_token, refresh_token }                       │
└──────────────────────────────────────────────────────────┘
```

**Code:**

```python
from pwdlib import PasswordHash
import jwt
from datetime import datetime, timedelta
import secrets

async def login(email: str, password: str) -> tuple[str, str]:
    user = await user_repo.find_by_email(email)
    if not user:
        raise InvalidCredentialsError()

    if not verify_password(password, user.hashed_password):
        raise InvalidCredentialsError()

    access_token = create_access_token(user)
    refresh_token = create_refresh_token()

    await refresh_token_repo.create(
        user_id=user.id,
        token_hash=hash_token(refresh_token),
        expires_at=datetime.utcnow() + timedelta(days=7),
    )

    return access_token, refresh_token
```

### Token Refresh Flow

```
┌──────────────────────────────────────────────────────────┐
│  1. Access token expires (after 15 min)                   │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  2. Client sends refresh token                            │
│     POST /api/v1/auth/refresh                             │
│     { refresh_token }                                     │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  3. Verify refresh token                                  │
│     - Hash token and lookup in DB                         │
│     - Check not expired                                   │
│     - Check not revoked                                   │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  4. Token rotation                                        │
│     - DELETE old refresh token                            │
│     - CREATE new refresh token                            │
│     - Store new hash in DB                                │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  5. Generate new access token                             │
│     - Increment token_version if needed                   │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  6. Return new tokens                                     │
│     { access_token, refresh_token }                       │
└──────────────────────────────────────────────────────────┘
```

**Why rotate refresh tokens?**
- Each refresh token is single-use
- If stolen, attacker can only use it once
- Original token becomes invalid
- User notices they're logged out

### Token Rotation Attack Detection

**Scenario:** Attacker steals refresh token

```
Time 0: Legitimate user has token A
Time 1: Attacker steals token A
Time 2: User refreshes → gets token B (token A deleted)
Time 3: Attacker tries to use token A → DETECTED!
```

**Detection mechanism:**

```python
async def refresh_token(token: str) -> tuple[str, str]:
    token_hash = hash_token(token)
    stored_token = await refresh_token_repo.find_by_hash(token_hash)

    if not stored_token:
        family_tokens = await refresh_token_repo.find_by_family_id(
            extract_family_id(token)
        )
        if family_tokens:
            await refresh_token_repo.delete_all(family_tokens)
            raise TokenReuseDetectedError()
        raise InvalidTokenError()

    # ...
```

If a deleted token is used, we:
1. Find all tokens in the same family
2. Delete them all (logout all devices)
3. Notify user of suspicious activity

### Token Versioning

**Problem:** How to invalidate all tokens instantly?

**Solution:** Token version field

```python
class User(Base):
    token_version: Mapped[int] = mapped_column(default=0)

def create_access_token(user: User) -> str:
    payload = {
        "sub": str(user.id),
        "token_version": user.token_version,  # ← Include version
        "exp": datetime.utcnow() + timedelta(minutes=15),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

async def verify_access_token(token: str) -> User:
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    user = await user_repo.get_by_id(payload["sub"])

    if user.token_version != payload["token_version"]:  # ← Check version
        raise InvalidTokenError("Token invalidated")

    return user
```

**When to increment token_version:**
- User changes password
- User reports token theft
- Admin resets user's sessions

```python
def change_password(user: User, new_password: str):
    user.hashed_password = hash_password(new_password)
    user.token_version += 1  # ← Invalidate all tokens
    await session.commit()
```

---

## Authorization

### Role-Based Access Control (RBAC)

**Roles:**
- `USER` - Regular researcher (can submit reports)
- `COMPANY` - Program owner (can create programs, triage reports)
- `ADMIN` - Platform admin (can access admin panel)

**Implementation:**

```python
from enum import StrEnum

class UserRole(StrEnum):
    USER = "user"
    COMPANY = "company"
    ADMIN = "admin"
    UNKNOWN = "unknown"  # For guest users

class RequireRole:
    def __init__(self, *allowed_roles: UserRole):
        self.allowed_roles = allowed_roles

    async def __call__(self, user: CurrentUser) -> User:
        if user.role not in self.allowed_roles:
            raise ForbiddenError()
        return user

# Usage
AdminOnly = Annotated[User, Depends(RequireRole(UserRole.ADMIN))]

@router.get("/admin/stats")
async def get_stats(user: AdminOnly) -> StatsResponse:
    # Only admins can access
    ...
```

### Resource Ownership

**Example:** Only program owner can update program

```python
@router.patch("/programs/{slug}")
async def update_program(
    slug: str,
    data: ProgramUpdate,
    user: CurrentUser,
    session: DatabaseSession,
) -> ProgramResponse:
    program = await program_repo.get_by_slug(slug)
    if not program:
        raise NotFoundError()

    if program.company_id != user.id and user.role != UserRole.ADMIN:
        raise ForbiddenError("You don't own this program")

    await program_repo.update(program, data)
    await session.commit()
    return ProgramResponse.from_orm(program)
```

**Authorization matrix:**

| Action | USER | COMPANY | ADMIN |
|--------|------|---------|-------|
| Submit report | ✓ (to any program) | ✓ | ✓ |
| Create program | ✓ | ✓ | ✓ |
| Triage report | ✗ | ✓ (own programs) | ✓ |
| Delete program | ✗ | ✓ (own programs) | ✓ |
| View admin panel | ✗ | ✗ | ✓ |

---

## Password Security

### Argon2id Hashing

**Why Argon2id?**
- Winner of Password Hashing Competition (2015)
- Memory-hard (resists GPU/ASIC attacks)
- Configurable (can increase cost over time)
- Side-channel resistant

**Comparison:**

| Algorithm | Security | Speed | Memory | Adoption |
|-----------|----------|-------|--------|----------|
| MD5 | ✗✗✗ | Fast | Low | Deprecated |
| SHA-256 | ✗ | Fast | Low | Don't use for passwords |
| bcrypt | ✓✓ | Slow | Medium | Good |
| Argon2id | ✓✓✓ | Slower | High | Best |

**Implementation:**

```python
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

password_hash = PasswordHash((Argon2Hasher(),))

def hash_password(password: str) -> str:
    return password_hash.hash(password)
    # → $argon2id$v=19$m=65536,t=3,p=4$...

def verify_password(password: str, hash: str) -> bool:
    try:
        return password_hash.verify(password, hash)
    except Exception:
        return False  # Invalid hash or password
```

**Hash format:**

```
$argon2id$v=19$m=65536,t=3,p=4$salt$hash
│         │   │ │      │  │
│         │   │ │      │  └─ Parallelism (4 threads)
│         │   │ │      └─ Time cost (3 iterations)
│         │   │ └─ Memory cost (64 MiB)
│         │   └─ Version 19
│         └─ Variant (argon2id)
└─ Algorithm
```

### Timing-Safe Password Verification

**Vulnerable code:**

```python
def verify_password_BAD(password: str, hash: str) -> bool:
    if hash_password(password) == hash:
        return True
    else:
        return False  # Early return reveals info!
```

**Timing attack:**
- Attacker measures response time
- Correct password takes longer (database lookup, session creation)
- Incorrect password returns immediately
- Attacker can brute-force faster

**Secure code:**

```python
def verify_password_GOOD(password: str, hash: str) -> bool:
    result = password_hash.verify(password, hash)
    # Always takes same time (Argon2id is constant-time)
    return result
```

### Password Requirements

**Enforced via Pydantic:**

```python
from pydantic import BaseModel, Field, field_validator

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain digit")
        return v
```

**Requirements:**
- Minimum 8 characters
- Maximum 128 characters (prevent DoS via long passwords)
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

---

## Token Security

### Storing Refresh Tokens

**Never store plaintext tokens!**

```python
# BAD - plaintext token in database
refresh_token = secrets.token_urlsafe(32)
await db.execute(
    "INSERT INTO refresh_tokens (token) VALUES (?)",
    (refresh_token,)
)

# GOOD - hash token before storing
refresh_token = secrets.token_urlsafe(32)
token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
await db.execute(
    "INSERT INTO refresh_tokens (token_hash) VALUES (?)",
    (token_hash,)
)
```

**Why hash?**
- If database is compromised, attacker can't use tokens
- Must have original token to authenticate
- Similar to password hashing

### JWT Secret Key

**Generate strong secret:**

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
# → x8J9kL2mN4pQ5rS7tU8vW1xY3zA5bC7dE9fG1hI3jK5m
```

**Requirements:**
- Minimum 32 bytes (256 bits)
- Random (use `secrets` module, not `random`)
- Never commit to Git
- Rotate periodically

**Environment variable:**

```bash
# .env
SECRET_KEY=x8J9kL2mN4pQ5rS7tU8vW1xY3zA5bC7dE9fG1hI3jK5m
```

**If key is compromised:**
- Attacker can forge JWT tokens
- Attacker can impersonate any user
- Must rotate key and invalidate all tokens

### Token Expiration

**Access token: 15 minutes**
- Balances security (short window if stolen) and UX (not too frequent refresh)
- Can be shorter (5 min) for high-security apps
- Can be longer (1 hour) for low-risk apps

**Refresh token: 7 days**
- Prevents indefinite access
- User must login again after 7 days
- Can be shorter (1 day) for high-security apps
- Can be longer (30 days) with "remember me" option

---

## Input Validation

### Pydantic Validation

**All input validated before reaching business logic:**

```python
from pydantic import BaseModel, EmailStr, Field, HttpUrl

class ProgramCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=255, pattern=r'^[a-z0-9-]+$')
    description: str | None = Field(None, max_length=10000)
    website: HttpUrl | None = None

# Usage
@router.post("/programs")
async def create_program(data: ProgramCreate):
    # At this point, data is validated:
    # - name is 1-255 chars
    # - slug matches pattern (lowercase, digits, hyphens)
    # - description is max 10,000 chars
    # - website is valid URL (if provided)
    ...
```

**Benefits:**
- Prevents SQL injection (parameterized queries)
- Prevents XSS (HTML is escaped on frontend)
- Prevents buffer overflow (string length limits)
- Clear error messages

### String Length Limits

**Why limit lengths?**
- Prevent DoS attacks (1GB string in database)
- Database column constraints
- UX (no 10,000-character names)

**Constants:**

```python
# config.py
EMAIL_MAX_LENGTH = 255
PASSWORD_HASH_MAX_LENGTH = 255
FULL_NAME_MAX_LENGTH = 255
PROGRAM_NAME_MAX_LENGTH = 255
PROGRAM_SLUG_MAX_LENGTH = 255
REPORT_TITLE_MAX_LENGTH = 255
CWE_ID_MAX_LENGTH = 20
```

**Applied to models:**

```python
class User(Base):
    email: Mapped[str] = mapped_column(String(EMAIL_MAX_LENGTH))
    full_name: Mapped[str | None] = mapped_column(String(FULL_NAME_MAX_LENGTH))
```

---

## Rate Limiting

### Why Rate Limiting?

**Attacks prevented:**
- Brute-force password guessing
- API abuse (scraping, spam)
- DoS attacks

**Implementation:**

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,  # Rate limit by IP
    default_limits=["100 per minute"],  # Global default
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Different limits for different endpoints
@router.post("/auth/login")
@limiter.limit("20/minute")  # Stricter for auth
async def login(...):
    ...

@router.get("/programs")
@limiter.limit("100/minute")  # Relaxed for public endpoints
async def list_programs(...):
    ...
```

**Configuration:**

```python
# .env
RATE_LIMIT_DEFAULT=100/minute
RATE_LIMIT_AUTH=20/minute
```

**Response when rate limited:**

```http
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1704123456
Retry-After: 60

{
  "error": "Rate limit exceeded. Try again in 60 seconds."
}
```

### Per-User Rate Limiting

**More sophisticated: Limit by authenticated user**

```python
def get_rate_limit_key(request: Request) -> str:
    if request.state.user:
        return f"user:{request.state.user.id}"
    return f"ip:{request.client.host}"

limiter = Limiter(key_func=get_rate_limit_key)
```

**Benefits:**
- Authenticated users get separate quota
- Can't share rate limit across IPs
- Can offer premium tiers (higher limits)

---

## Common Vulnerabilities Prevented

### SQL Injection

**Vulnerable code:**

```python
# BAD - concatenating user input
email = request.args.get("email")
query = f"SELECT * FROM users WHERE email = '{email}'"
result = await db.execute(query)
```

**Attack:**

```
email=admin@example.com' OR '1'='1
→ SELECT * FROM users WHERE email = 'admin@example.com' OR '1'='1'
→ Returns all users!
```

**Secure code:**

```python
# GOOD - parameterized query
stmt = select(User).where(User.email == email)
result = await session.execute(stmt)
```

SQLAlchemy automatically escapes parameters.

### Cross-Site Scripting (XSS)

**Vulnerable code:**

```html
<!-- BAD - raw HTML injection -->
<div>{user.bio}</div>
```

**Attack:**

```
bio=<script>alert('XSS')</script>
→ <div><script>alert('XSS')</script></div>
→ Script executes!
```

**Secure code:**

```jsx
// React automatically escapes
<div>{user.bio}</div>
// → <div>&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
```

**For markdown:**

```python
import markdown
from bleach import clean

def render_markdown(text: str) -> str:
    html = markdown.markdown(text)
    return clean(
        html,
        tags=['p', 'br', 'strong', 'em', 'code', 'pre'],
        strip=True,
    )
```

### Cross-Site Request Forgery (CSRF)

**Not vulnerable because we use JWT tokens:**
- CSRF requires cookies (sent automatically)
- JWT tokens are in `Authorization` header (must be sent explicitly)
- Attacker can't read `Authorization` header from another domain

**If using cookies, would need CSRF tokens:**

```python
from fastapi_csrf import CsrfProtect

@app.post("/login")
async def login(csrf_protect: CsrfProtect = Depends()):
    await csrf_protect.validate_csrf(request)
    ...
```

### Insecure Direct Object References (IDOR)

**Vulnerable code:**

```python
# BAD - no authorization check
@router.get("/reports/{report_id}")
async def get_report(report_id: UUID):
    report = await report_repo.get_by_id(report_id)
    return report  # Anyone can access any report!
```

**Secure code:**

```python
# GOOD - check ownership
@router.get("/reports/{report_id}")
async def get_report(report_id: UUID, user: CurrentUser):
    report = await report_repo.get_by_id(report_id)
    if not report:
        raise NotFoundError()

    if (report.researcher_id != user.id and
        report.program.company_id != user.id and
        user.role != UserRole.ADMIN):
        raise ForbiddenError()

    return report
```

---

## Security Best Practices

### 1. Least Privilege

**Give users only the permissions they need:**

```python
# BAD - everyone is admin
user.role = UserRole.ADMIN

# GOOD - specific roles
user.role = UserRole.USER  # Can only submit reports
```

### 2. Defense in Depth

**Multiple layers of security:**
1. Input validation (Pydantic)
2. Authentication (JWT)
3. Authorization (RBAC)
4. Rate limiting
5. Encryption in transit (HTTPS)
6. Encryption at rest (encrypted database)

### 3. Secure Defaults

**Default to secure, opt-in to insecure:**

```python
# BAD - default allows everything
CORS_ORIGINS = ["*"]

# GOOD - default is restrictive
CORS_ORIGINS = ["https://example.com"]
```

### 4. Security Headers

**Add security headers via Nginx:**

```nginx
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self'";
```

### 5. Error Messages

**Don't leak information in errors:**

```python
# BAD - reveals whether email exists
if not user:
    raise HTTPException(status_code=404, detail="User not found")
if not verify_password(password, user.hashed_password):
    raise HTTPException(status_code=401, detail="Invalid password")

# GOOD - generic error
if not user or not verify_password(password, user.hashed_password):
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

### 6. Logging and Monitoring

**Log security events:**

```python
import structlog

logger = structlog.get_logger()

@router.post("/auth/login")
async def login(email: str, password: str):
    user = await user_repo.find_by_email(email)

    if not user:
        logger.warning("login_failed", email=email, reason="user_not_found")
        raise InvalidCredentialsError()

    if not verify_password(password, user.hashed_password):
        logger.warning("login_failed", email=email, reason="invalid_password")
        raise InvalidCredentialsError()

    logger.info("login_success", user_id=user.id, email=email)
    # ...
```

**Monitor for:**
- Failed login attempts
- Rate limit violations
- Token reuse attempts
- Unusual activity patterns

### 7. Dependency Security

**Regularly update dependencies:**

```bash
# Check for vulnerabilities
pip-audit

# Update dependencies
pip install --upgrade -r requirements.txt
```

**Use Dependabot or Renovate:**
- Automatic PR for dependency updates
- Includes security patches

### 8. Secrets Management

**Never commit secrets to Git:**

```bash
# .gitignore
.env
*.pem
*.key
secrets/
```

**Use environment variables:**

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str  # Read from .env or environment
    DATABASE_URL: str
```

**For production, use secret managers:**
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault

---

## Conclusion

Security is **not an afterthought**, it's designed into every layer:

1. **Authentication** - JWT with token rotation
2. **Authorization** - RBAC with resource ownership
3. **Password Security** - Argon2id hashing
4. **Token Security** - Hashed storage, token versioning
5. **Input Validation** - Pydantic schemas
6. **Rate Limiting** - Per-IP and per-user
7. **Vulnerability Prevention** - SQL injection, XSS, CSRF, IDOR

For more information:
- System architecture: [ARCHITECTURE.md](./ARCHITECTURE.md)
- Design patterns: [PATTERNS.md](./PATTERNS.md)
- Database design: [DATABASE.md](./DATABASE.md)
- Hands-on tutorial: [GETTING-STARTED.md](./GETTING-STARTED.md)

**Remember:** Security is a journey, not a destination. Stay updated on best practices and common vulnerabilities.
