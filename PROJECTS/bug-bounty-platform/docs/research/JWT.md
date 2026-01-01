# JWT Authentication for FastAPI + PostgreSQL: 2025 Production Patterns

**The recommended stack for production JWT authentication in 2025 is PyJWT 2.10+ with Argon2id (via argon2-cffi), rotating refresh tokens stored hashed in PostgreSQL, and Redis for rate limiting and instant revocation.** FastAPI's deprecation of python-jose in favor of PyJWT, combined with passlib's unmaintained status since 2020, marks a significant shift in the ecosystem. This report covers the deep implementation patterns, anti-patterns, and security considerations needed to build a production-ready auth system.

---

## JWT library landscape has shifted dramatically

**PyJWT 2.10.1** is now the FastAPI-endorsed choice after python-jose's effective deprecation (last meaningful release ~2021). Key 2024-2025 updates include built-in `sub` and `jti` claim validation, `strict_aud` for stricter audience checks, and Ed448/EdDSA support.

```python
# Production PyJWT configuration (2025)
import jwt
from datetime import datetime, timedelta, UTC

def create_access_token(user_id: str, roles: list[str]) -> str:
    return jwt.encode(
        {
            "sub": user_id,
            "exp": datetime.now(UTC) + timedelta(minutes=15),
            "iat": datetime.now(UTC),
            "jti": str(uuid.uuid4()),  # For revocation
            "type": "access",
            "roles": roles,
            "token_version": user.token_version,  # For "logout all"
        },
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm="HS256"
    )

def decode_token(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithms=["HS256"],  # NEVER trust token header
        options={"require": ["exp", "sub", "jti", "iat"]}
    )
```

**joserfc** (from Authlib team) emerges as the modern alternative when JWE encryption is needed or stricter type safety is required. For most FastAPI applications, PyJWT remains the pragmatic choice due to ecosystem maturity and FastAPI documentation alignment.

### Token expiration and rotation strategy

Production consensus for **access tokens is 15 minutes**, **refresh tokens 7-14 days with rotation**. The critical pattern is **rotating refresh tokens with token families** for theft detection:

```python
# Token family pattern prevents replay attacks
{
    "sub": "user_123",
    "jti": "unique-token-id",
    "family_id": "auth-session-uuid",  # All tokens from same login share this
    "type": "refresh",
    "exp": 1234567890
}
```

When a refresh token is used, issue a **new refresh token and invalidate the old one**. If a previously-invalidated token is presented (replay attack), **revoke the entire token family** immediately—this catches the race condition between legitimate user and attacker.

### Storage strategy: Memory + HttpOnly cookies

The 2025 consensus is clear: **access tokens in JavaScript memory** (React state/closures, never localStorage), **refresh tokens in HttpOnly cookies**:

```python
def set_refresh_cookie(response: Response, token: str):
    response.set_cookie(
        key="refresh_token",
        value=token,
        httponly=True,
        secure=True,               # HTTPS only
        samesite="strict",         # CSRF protection
        max_age=604800,            # 7 days
        path="/api/auth/refresh"   # Limit scope to refresh endpoint
    )
```

For high-security applications, the **Backend-for-Frontend (BFF) pattern** keeps tokens entirely server-side—the SPA receives only a session cookie while the BFF proxies API requests with injected access tokens.

---

## Password hashing requires Argon2id with specific parameters

**passlib is effectively dead**—last release October 2020, breaks on Python 3.13+. Use **argon2-cffi 25.1.0** or the newer **pwdlib 0.3.0** (from FastAPI-users maintainer).

OWASP's 2025 minimum parameters for Argon2id: **19 MiB memory, 2 iterations, 1 parallelism**, targeting ~500ms hash time:

```python
from argon2 import PasswordHasher
import asyncio

# OWASP minimum configuration
ph = PasswordHasher(
    time_cost=2,        # iterations
    memory_cost=19456,  # 19 MiB
    parallelism=1,      # Important: p=1 for async FastAPI
    hash_len=32,
    salt_len=16
)

async def hash_password(password: str) -> str:
    # CPU-bound - run in thread pool for async FastAPI
    return await asyncio.to_thread(ph.hash, password)

async def verify_password(hash: str, password: str) -> tuple[bool, str | None]:
    """Returns (is_valid, new_hash_if_needs_rehash)"""
    try:
        await asyncio.to_thread(ph.verify, hash, password)
        if ph.check_needs_rehash(hash):  # Auto-upgrade old parameters
            return True, await hash_password(password)
        return True, None
    except:
        return False, None
```

**Argon2id handles salts internally**—16-byte salt is automatically generated and embedded in the output hash. Separate salt storage is unnecessary. For additional defense, a **pepper** (application-level secret stored in secrets vault) can wrap the hash via HMAC, but requires all users to reset passwords if the pepper changes.

### Password reset must prevent timing attacks and enumeration

```python
async def request_reset(email: str):
    start = datetime.now()
    user = await get_user_by_email(email)
    
    if user:
        token = secrets.token_urlsafe(32)  # 256 bits
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        await store_reset_token(user.id, token_hash, expires=timedelta(hours=1))
        await send_email(email, token)
    
    # CRITICAL: Consistent timing prevents user enumeration
    elapsed = (datetime.now() - start).total_seconds()
    if elapsed < 0.5:
        await asyncio.sleep(0.5 - elapsed)
    
    # Always same response
    return {"message": "If an account exists, reset email sent"}
```

Store reset tokens as **SHA-256 hashes** (treat like passwords), expire within **15-60 minutes**, enforce **one-time use** by marking used before changing password.

---

## FastAPI auth patterns favor dependencies over middleware

**Dependencies are the FastAPI-native pattern for authentication**—more testable, composable, and efficient than middleware which runs on every request including `/docs`.

### Standard dependency chain

```python
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="api/v1/auth/token",
    scopes={"read": "Read access", "write": "Write access", "admin": "Admin access"}
)

async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)]
) -> User:
    try:
        payload = decode_token(token)
        if await is_token_revoked(payload["jti"]):
            raise HTTPException(status_code=401, detail="Token revoked")
        user = await get_user(payload["sub"])
        if payload.get("token_version") != user.token_version:
            raise HTTPException(status_code=401, detail="Session invalidated")
        return user
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_active_user(
    user: Annotated[User, Depends(get_current_user)]
) -> User:
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user

async def get_admin_user(
    user: Annotated[User, Depends(get_current_active_user)]
) -> User:
    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Admin required")
    return user
```

### Optional authentication uses auto_error=False

```python
optional_oauth2 = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

async def get_optional_user(
    token: str | None = Depends(optional_oauth2)
) -> User | None:
    if not token:
        return None
    try:
        payload = decode_token(token)
        return await get_user(payload["sub"])
    except:
        return None
```

### RBAC with callable permission checker classes

```python
class PermissionChecker:
    def __init__(self, required_permissions: list[str]):
        self.required = required_permissions

    def __call__(self, user: User = Depends(get_current_active_user)):
        for perm in self.required:
            if perm not in user.permissions:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
        return True

# Usage
@app.get("/items/", dependencies=[Depends(PermissionChecker(["read:items"]))])
def list_items(): ...

@app.delete("/items/{id}", dependencies=[Depends(PermissionChecker(["delete:items"]))])
def delete_item(id: int): ...
```

For **route group auth**, use APIRouter dependencies:

```python
protected_router = APIRouter(
    prefix="/api/v1",
    dependencies=[Depends(get_current_active_user)]
)
admin_router = APIRouter(
    prefix="/api/v1/admin",
    dependencies=[Depends(get_admin_user)]
)
```

---

## Database schema requires hashed token storage and family tracking

**Use UUID primary keys** for user tables—the ~13% performance penalty versus integers is acceptable for the security benefit of not exposing record counts. PostgreSQL 18 (Fall 2025) will introduce UUID v7 with timestamp ordering for better index performance.

### Core user model

```python
class User(Base):
    __tablename__ = "users"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(1024))
    
    is_active: Mapped[bool] = mapped_column(default=True)
    is_verified: Mapped[bool] = mapped_column(default=False)
    is_superuser: Mapped[bool] = mapped_column(default=False)
    
    # Critical for "logout all devices"
    token_version: Mapped[int] = mapped_column(default=0)
    
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(onupdate=func.now())
    last_login: Mapped[datetime | None]
    
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"  # Required for async SQLAlchemy
    )
```

### Refresh token table with family tracking

```python
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    
    # ALWAYS hash stored tokens
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    
    # Device tracking for "active sessions" UI
    device_id: Mapped[str | None] = mapped_column(String(255))
    device_name: Mapped[str | None] = mapped_column(String(100))
    ip_address: Mapped[str | None] = mapped_column(String(45))  # IPv6 length
    
    # Token family for rotation attack detection
    family_id: Mapped[UUID] = mapped_column(default=uuid4, index=True)
    
    expires_at: Mapped[datetime] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    
    is_revoked: Mapped[bool] = mapped_column(default=False)
    revoked_at: Mapped[datetime | None]
```

### Token rotation with replay attack detection

```python
async def rotate_refresh_token(db: AsyncSession, old_token: str, user_id: UUID) -> tuple[str, str]:
    old_hash = hashlib.sha256(old_token.encode()).hexdigest()
    
    existing = await db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == old_hash,
            RefreshToken.is_revoked == False
        )
    )
    
    if not existing:
        # REPLAY ATTACK - Revoke entire token family
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id)
            .values(is_revoked=True, revoked_at=func.now())
        )
        await db.commit()
        raise SecurityException("Token reuse detected - all sessions revoked")
    
    # Revoke old, issue new with same family
    existing.is_revoked = True
    existing.revoked_at = datetime.now(UTC)
    
    new_token = secrets.token_urlsafe(32)
    new_refresh = RefreshToken(
        token_hash=hashlib.sha256(new_token.encode()).hexdigest(),
        user_id=user_id,
        family_id=existing.family_id,  # Same family
        expires_at=datetime.now(UTC) + timedelta(days=7)
    )
    db.add(new_refresh)
    await db.commit()
    
    return new_token, create_access_token(user_id)
```

### "Logout all devices" via token_version

```python
async def logout_all_devices(db: AsyncSession, user_id: UUID):
    await db.execute(
        update(User).where(User.id == user_id)
        .values(token_version=User.token_version + 1)
    )
    await db.execute(
        update(RefreshToken).where(RefreshToken.user_id == user_id)
        .values(is_revoked=True)
    )
    await db.commit()
```

All access tokens immediately become invalid when `token_version` in the token doesn't match the user's current `token_version`.

---

## Security hardening requires defense in depth

### CORS with credentials requires explicit origins

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourapp.com"],  # NEVER ["*"] with credentials
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
    max_age=600,  # Cache preflight 10 minutes
)
```

### Rate limiting is mandatory for auth endpoints

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="redis://localhost:6379"
)

@app.post("/auth/login")
@limiter.limit("5/minute")
async def login(request: Request): ...

@app.post("/auth/password-reset")
@limiter.limit("3/hour")
async def password_reset(request: Request): ...
```

Implement **progressive lockout**: 5 failed attempts → 1 minute lock, 10 → 5 minutes, 15 → 30 minutes.

### Timing attack prevention requires dummy operations

```python
# Pre-compute at startup
DUMMY_HASH = ph.hash("dummy_password_for_timing")

async def authenticate(username: str, password: str) -> User | None:
    user = await get_user_by_email(username)
    
    if user is None:
        # Perform dummy hash to prevent timing attack
        await asyncio.to_thread(ph.verify, password, DUMMY_HASH)
        return None
    
    valid, _ = await verify_password(user.hashed_password, password)
    return user if valid else None
```

Use `secrets.compare_digest()` for all token comparisons—never `==`.

### RS256 over HS256 for production multi-service architectures

For microservices, **RS256 (asymmetric)** allows distributing public keys for verification while keeping private keys isolated. Key rotation becomes simpler—only public keys need updating across services.

```python
# Key rotation with kid (key ID) in header
def sign_token(payload: dict, private_key: str, kid: str) -> str:
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

def verify_token(token: str, public_keys: dict) -> dict:
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    return jwt.decode(token, public_keys[kid], algorithms=["RS256"])
```

---

## Production deployment checklist

### Secrets management with pydantic-settings

```python
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        secrets_dir="/run/secrets"  # Docker secrets
    )
    
    JWT_SECRET_KEY: SecretStr
    DATABASE_URL: SecretStr
    REDIS_URL: str
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
```

### Auth event logging (GDPR-compliant)

**Log**: login attempts/success/failure, password changes, token refresh, session invalidation
**Never log**: passwords, full tokens, session IDs, unnecessary PII

```python
logger.info("auth_event", 
    event_type="login_success",
    user_id=user.id,  # Pseudonymized ID, not email
    ip_address=mask_ip(request.client.host),  # Mask last octet
    timestamp=datetime.utcnow().isoformat()
)
```

### Docker security essentials

```dockerfile
# Non-root user
RUN useradd -r -g appgroup appuser
USER appuser

# Multi-stage build
FROM python:3.12-slim AS runtime
COPY --from=builder /app/requirements.txt .
```

Use Docker secrets (`/run/secrets/`) instead of environment variables for sensitive data in production.

---

## Critical anti-patterns to avoid

- **Storing sensitive data in JWT payload** - tokens are base64, not encrypted
- **Not explicitly specifying algorithms** on decode - enables algorithm confusion attacks
- **Using passlib in new projects** - unmaintained, breaks on Python 3.13+
- **Trusting `alg` header from token** - always validate with explicit `algorithms=["HS256"]`
- **Using `["*"]` with `allow_credentials=True`** in CORS - browsers reject this
- **Comparing tokens with `==`** instead of `secrets.compare_digest()`
- **Not running password hashing in thread pool** - blocks async event loop
- **Storing raw refresh tokens** - always hash before storage
- **Missing token family tracking** - enables silent replay attacks

## Conclusion

Building production-ready JWT authentication in FastAPI requires careful attention to the shifting ecosystem (PyJWT over python-jose, argon2-cffi over passlib), proper token rotation with family tracking, and defense-in-depth security measures. The patterns outlined here—dependency-based auth, hashed token storage, timing attack prevention, and progressive rate limiting—form a robust foundation that scales from single applications to distributed microservices architectures.
