# 02-ARCHITECTURE.md

# System Architecture

This document breaks down how the system is designed and why certain architectural decisions were made.

## High Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Client Browser                          │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP/HTTPS
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Nginx Reverse Proxy                         │
│  - Routes /api/* → Backend (FastAPI)                            │
│  - Routes /* → Frontend (Static Files)                          │
│  - Handles CORS, compression, caching                           │
└──────────────┬─────────────────────────┬────────────────────────┘
               │                         │
               ▼                         ▼
┌──────────────────────────┐   ┌─────────────────────────────────┐
│   Backend (FastAPI)      │   │   Frontend (React/Vite)         │
│  ┌────────────────────┐  │   │  ┌───────────────────────────┐  │
│  │     Routes         │  │   │  │    Components             │  │
│  │  /auth, /scans     │  │   │  │  Auth, Scan UI            │  │
│  └─────────┬──────────┘  │   │  └─────────┬─────────────────┘  │
│            ▼              │   │            │                    │
│  ┌────────────────────┐  │   │  ┌───────────────────────────┐  │
│  │    Services        │  │   │  │    TanStack Query         │  │
│  │  Business Logic    │  │   │  │  Server State Mgmt        │  │
│  └─────────┬──────────┘  │   │  └─────────┬─────────────────┘  │
│            ▼              │   │            │                    │
│  ┌────────────────────┐  │   │  ┌───────────────────────────┐  │
│  │   Repositories     │  │   │  │    Zustand Stores         │  │
│  │  Data Access       │  │   │  │  Local State Mgmt         │  │
│  └─────────┬──────────┘  │   │  └───────────────────────────┘  │
│            │              │   │                                 │
│  ┌─────────▼──────────┐  │   └─────────────────────────────────┘
│  │    Scanners        │  │
│  │  RateLimit, Auth,  │  │
│  │  SQLi, IDOR        │  │
│  └────────────────────┘  │
└──────────────┬────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                           │
│  Tables: users, scans, test_results                             │
└─────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

**Nginx Reverse Proxy**
- Purpose: Single entry point for all HTTP traffic
- Responsibilities: Route requests based on path, serve static files, handle SSL termination (production), compress responses, cache static assets
- Interfaces: Exposes port 80 (HTTP) and optionally 443 (HTTPS), proxies to backend on internal port 8000

**FastAPI Backend**
- Purpose: REST API server providing authentication and scanning services
- Responsibilities: Validate requests, enforce authentication, execute security scans, store results, return JSON responses
- Interfaces: Exposes HTTP endpoints at `/auth/*` and `/scans/*`, connects to PostgreSQL for data persistence

**React Frontend**
- Purpose: User interface for creating scans and viewing results
- Responsibilities: Form validation, API communication, state management, result visualization
- Interfaces: Communicates with backend via `/api` prefix, renders in browser

**PostgreSQL Database**
- Purpose: Persistent storage for users, scans, and test results
- Responsibilities: Data integrity, relationship enforcement, query optimization
- Interfaces: Accepts connections from backend on port 5432, enforces foreign key constraints

**Scanner Modules**
- Purpose: Execute security tests against target APIs
- Responsibilities: Send HTTP requests, analyze responses, detect vulnerabilities, collect evidence
- Interfaces: Inherit from `BaseScanner`, return `TestResultCreate` schemas

## Data Flow

### Primary Use Case: Creating and Running a Scan

Step by step walkthrough of what happens when a user submits a new scan:

```
1. User submits form → Frontend validates (Zod schema)
   Input: { targetUrl, authToken, testsToRun, maxRequests }
   Validation happens at frontend/src/lib/validation.ts:42-52

2. Frontend → POST /api/scans/ → Nginx
   Adds Authorization header with JWT from localStorage
   Request routed based on /api prefix

3. Nginx → Backend (routes/scans.py:23-37)
   Proxy passes to http://backend:8000/scans/
   Preserves headers including Authorization

4. Route handler → Dependencies check auth
   @limiter.limit("15/minute") - rate limits this endpoint
   get_current_user() extracts JWT, validates, loads user from DB
   Code at backend/core/dependencies.py:17-49

5. Route → Service layer (services/scan_service.py:23-65)
   ScanService.run_scan(db, user_id, scan_request)
   Creates Scan record in database via repository

6. Service → Scanner modules (scanners/*.py)
   Loops through requested tests (rate_limit, auth, sqli, idor)
   Instantiates appropriate scanner class for each test
   Each scanner inherits from BaseScanner

7. Scanner → Target API
   Makes HTTP requests using requests.Session
   Implements retry logic, rate limiting, timeout handling
   Base logic at backend/scanners/base_scanner.py:40-156

8. Scanner analyzes responses → Returns TestResultCreate
   Detects vulnerabilities based on:
   - Status codes (429 for rate limiting)
   - Response content (SQL errors)
   - Timing differences (blind SQLi)
   - Header patterns (JWT algorithms)

9. Service saves results → Repository → Database
   TestResultRepository.create_test_result() for each scanner output
   Foreign key links results to scan
   Code at backend/repositories/test_result_repository.py:19-50

10. Service → Route → JSON response
    ScanResponse includes full scan with nested test_results
    Frontend receives and redirects to /scans/{id}

11. Frontend fetches full scan → GET /api/scans/{id}
    TanStack Query caches result
    Renders TestResultCard for each result
```

Example with code references:

```python
# Step 5: Route handler
@router.post("/", response_model=ScanResponse)
@limiter.limit(settings.API_RATE_LIMIT_SCAN)  # "15/minute"
async def create_scan(
    request: Request,
    scan_request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),  # Auth check
) -> ScanResponse:
    return ScanService.run_scan(db, current_user.id, scan_request)

# Step 6: Service orchestrates scanners
scanner_mapping: dict[TestType, type[BaseScanner]] = {
    TestType.RATE_LIMIT: RateLimitScanner,
    TestType.AUTH: AuthScanner,
    TestType.SQLI: SQLiScanner,
    TestType.IDOR: IDORScanner,
}

for test_type in scan_request.tests_to_run:
    scanner_class = scanner_mapping.get(test_type)
    scanner = scanner_class(
        target_url=str(scan_request.target_url),
        auth_token=scan_request.auth_token,
        max_requests=scan_request.max_requests,
    )
    result = scanner.scan()  # Execute the test
    results.append(result)

# Step 9: Save to database
for result in results:
    TestResultRepository.create_test_result(
        db=db,
        scan_id=scan.id,
        test_name=result.test_name,
        status=result.status,
        severity=result.severity,
        details=result.details,
        evidence_json=result.evidence_json,
        recommendations_json=result.recommendations_json,
    )
```

### Secondary Use Case: User Registration Flow

```
1. User fills registration form → Frontend validates
   Zod schema checks: email format, password strength (8+ chars, uppercase, lowercase, number)
   frontend/src/lib/validation.ts:17-31

2. POST /api/auth/register → Rate limited to 15/minute
   Prevents automated account creation abuse
   backend/routes/auth.py:25-42

3. Service checks if email exists → Repository query
   UserRepository.get_by_email() checks for duplicates
   Returns 400 if email already registered

4. Service hashes password with bcrypt
   core/security.py:11-18 uses bcrypt.gensalt() and hashpw()
   Salt automatically generated per password

5. Repository creates user record
   UserRepository.create_user(email, hashed_password)
   Sets is_active=True, created_at=UTC timestamp

6. Response returns user data (NOT password)
   UserResponse schema excludes hashed_password field
   Frontend redirects to login page
```

## Design Patterns

### Repository Pattern

**What it is:**
Abstraction layer between business logic and data access. All database queries go through repository classes that provide clean interfaces.

**Where we use it:**
- `repositories/user_repository.py` - User CRUD operations
- `repositories/scan_repository.py` - Scan queries with eager loading
- `repositories/test_result_repository.py` - Test result operations

**Why we chose it:**
Keeps services clean and testable. Services call `UserRepository.get_by_email(db, email)` instead of writing raw queries. If we switch from SQLAlchemy to a different ORM or database entirely, we only change repository implementations, not service logic.

**Trade-offs:**
- Pros: Testable (mock repositories), maintainable (queries in one place), flexible (swap implementations)
- Cons: Extra layer of abstraction, more files to navigate, can feel like overkill for simple CRUD

Example implementation:

```python
# repositories/user_repository.py:12-35
class UserRepository:
    """
    Repository for User database operations
    """
    @staticmethod
    def get_by_id(db: Session, user_id: int) -> User | None:
        return db.query(User).filter(User.id == user_id).first()
    
    @staticmethod
    def get_by_email(db: Session, email: str) -> User | None:
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def create_user(
        db: Session,
        email: str,
        hashed_password: str,
        commit: bool = True
    ) -> User:
        user = User(email=email, hashed_password=hashed_password)
        db.add(user)
        if commit:
            db.commit()
            db.refresh(user)
        return user
```

Services use it:

```python
# services/auth_service.py:24-32
existing_user = UserRepository.get_by_email(db, user_data.email)
if existing_user:
    raise HTTPException(status_code=400, detail="Email already registered")

hashed_password = hash_password(user_data.password)

user = UserRepository.create_user(
    db=db,
    email=user_data.email,
    hashed_password=hashed_password,
)
```

### Dependency Injection (FastAPI's Depends)

**What it is:**
FastAPI's dependency injection system automatically provides values to route handler parameters. Used for database sessions, authentication, rate limiting.

**Where we use it:**
Every route handler in `routes/auth.py` and `routes/scans.py` uses dependencies:

```python
# routes/scans.py:23-37
@router.post("/", response_model=ScanResponse)
@limiter.limit(settings.API_RATE_LIMIT_SCAN)
async def create_scan(
    request: Request,  # Injected by FastAPI
    scan_request: ScanRequest,  # Parsed and validated from request body
    db: Session = Depends(get_db),  # Database session injected
    current_user: UserResponse = Depends(get_current_user),  # Auth check injected
) -> ScanResponse:
    return ScanService.run_scan(db, current_user.id, scan_request)
```

**Why we chose it:**
Clean separation of concerns. The route handler doesn't know how to:
- Get a database session (handled by `get_db`)
- Validate JWT tokens (handled by `get_current_user`)
- Parse request bodies (handled by Pydantic)

This makes testing easier - mock the dependencies, not the entire request cycle.

**Trade-offs:**
- Pros: Testable, reusable, explicit dependencies, automatic cleanup (session closing)
- Cons: "Magic" behavior for beginners, debugging can be tricky if dependency fails

The `get_current_user` dependency implementation (`core/dependencies.py:17-49`):

```python
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    FastAPI dependency to extract and verify the current authenticated user
    """
    try:
        payload = decode_token(credentials.credentials)
        email: str | None = payload.get("sub")
        
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = UserRepository.get_by_email(db, email)
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return UserResponse.model_validate(user)
    
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
```

### Template Method (BaseScanner Abstract Class)

**What it is:**
Define the skeleton of an algorithm in a base class, let subclasses override specific steps. All scanners share common HTTP logic but implement their own `scan()` method.

**Where we use it:**
`scanners/base_scanner.py` provides common functionality:

```python
class BaseScanner(ABC):
    def __init__(self, target_url: str, auth_token: str | None = None, max_requests: int | None = None):
        self.target_url = target_url.rstrip("/")
        self.auth_token = auth_token
        self.max_requests = max_requests or settings.DEFAULT_MAX_REQUESTS
        self.session = self._create_session()
        self.last_request_time = 0.0
        self.request_count = 0
    
    def make_request(self, method: str, endpoint: str, **kwargs: Any) -> requests.Response:
        """Common HTTP request logic with retry and rate limiting"""
        self._wait_before_request()
        # ... retry logic, backoff, timeout handling
    
    def get_baseline_timing(self, endpoint: str, samples: int | None = None) -> tuple[float, float]:
        """Statistical baseline for time-based detection"""
        # ... takes samples, calculates mean and stdev
    
    @abstractmethod
    def scan(self) -> TestResultCreate:
        """Must be implemented by specific scanner classes"""
```

Subclasses implement `scan()`:

```python
# scanners/sqli_scanner.py:25-60
class SQLiScanner(BaseScanner):
    def scan(self) -> TestResultCreate:
        error_based_test = self._test_error_based_sqli()
        if error_based_test["vulnerable"]:
            return self._create_vulnerable_result(...)
        
        boolean_based_test = self._test_boolean_based_sqli()
        if boolean_based_test["vulnerable"]:
            return self._create_vulnerable_result(...)
        
        time_based_test = self._test_time_based_sqli()
        if time_based_test["vulnerable"]:
            return self._create_vulnerable_result(...)
        
        return TestResultCreate(status=ScanStatus.SAFE, ...)
```

**Why we chose it:**
Eliminates code duplication. Request spacing, retry logic, session management - written once in `BaseScanner`, used by all four scanner types.

**Trade-offs:**
- Pros: DRY principle, consistent behavior, easy to add new scanners
- Cons: Tight coupling to base class, inheritance can be limiting

## Layer Separation

The backend uses a three-layer architecture:

```
┌────────────────────────────────────┐
│    Layer 1: Routes                 │
│    - HTTP request/response         │
│    - Validation (Pydantic)         │
│    - Auth checks (dependencies)    │
│    - Rate limiting                 │
└────────────────┬───────────────────┘
                 ↓
┌────────────────────────────────────┐
│    Layer 2: Services               │
│    - Business logic                │
│    - Orchestration                 │
│    - Transaction management        │
│    - Error handling                │
└────────────────┬───────────────────┘
                 ↓
┌────────────────────────────────────┐
│    Layer 3: Repositories           │
│    - Database queries              │
│    - Data access only              │
│    - No business logic             │
└────────────────────────────────────┘
```

### Why Layers?

Separation makes each layer testable in isolation:
- Test routes with mocked services
- Test services with mocked repositories
- Test repositories against a real test database

It also enforces single responsibility. Routes don't write SQL. Services don't parse HTTP headers. Repositories don't implement business rules.

### What Lives Where

**Layer 1: Routes** (`routes/auth.py`, `routes/scans.py`)
- Files: Route handler functions decorated with `@router.get/post/delete`
- Imports: Can import from services, schemas, dependencies
- Forbidden: Direct database access, business logic, calling repositories directly

Example route:

```python
# routes/scans.py:67-83
@router.get("/{scan_id}", response_model=ScanResponse)
@limiter.limit(settings.API_RATE_LIMIT_DEFAULT)
async def get_scan(
    request: Request,
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
) -> ScanResponse:
    """
    Get a specific scan by ID
    """
    return ScanService.get_scan_by_id(db, scan_id, current_user.id)
```

**Layer 2: Services** (`services/auth_service.py`, `services/scan_service.py`)
- Files: Service classes with static methods
- Imports: Repositories, models, schemas, utilities
- Forbidden: HTTP-specific code (requests, responses), direct SQL queries

Example service method:

```python
# services/scan_service.py:23-65
@staticmethod
def run_scan(db: Session, user_id: int, scan_request: ScanRequest) -> ScanResponse:
    # Create scan record
    scan = ScanRepository.create_scan(
        db=db,
        user_id=user_id,
        target_url=str(scan_request.target_url),
    )
    
    # Map test types to scanner classes
    scanner_mapping: dict[TestType, type[BaseScanner]] = {
        TestType.RATE_LIMIT: RateLimitScanner,
        TestType.AUTH: AuthScanner,
        TestType.SQLI: SQLiScanner,
        TestType.IDOR: IDORScanner,
    }
    
    results: list[TestResultCreate] = []
    
    # Execute each requested test
    for test_type in scan_request.tests_to_run:
        scanner_class = scanner_mapping.get(test_type)
        scanner = scanner_class(...)
        result = scanner.scan()
        results.append(result)
    
    # Save all results
    for result in results:
        TestResultRepository.create_test_result(db=db, scan_id=scan.id, ...)
    
    db.refresh(scan)
    return ScanResponse.model_validate(scan)
```

**Layer 3: Repositories** (`repositories/user_repository.py`, `repositories/scan_repository.py`, `repositories/test_result_repository.py`)
- Files: Repository classes with static methods for database operations
- Imports: Models, SQLAlchemy, config
- Forbidden: Business logic, HTTP handling, calling other repositories

Example repository method:

```python
# repositories/scan_repository.py:48-71
@staticmethod
def get_by_user(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int | None = None
) -> list[Scan]:
    """
    Get all scans for a user with pagination
    """
    if limit is None:
        limit = settings.DEFAULT_PAGINATION_LIMIT
    
    return (
        db.query(Scan)
        .options(joinedload(Scan.test_results))  # Eager load relationships
        .filter(Scan.user_id == user_id)
        .order_by(Scan.scan_date.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
```

## Data Models

### User Model

```python
# models/User.py:12-43
class User(BaseModel):
    """
    Stores authentication credentials and user information
    """
    __tablename__ = "users"
    
    email = Column(
        String(settings.EMAIL_MAX_LENGTH),  # 255 chars
        unique=True,
        nullable=False,
        index=True,  # Fast lookups by email
    )
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
```

**Fields explained:**
- `id`: Auto-incrementing primary key (inherited from `BaseModel`)
- `email`: Unique identifier for login, indexed for fast authentication queries
- `hashed_password`: Bcrypt hash, never stored in plaintext, never returned in API responses
- `is_active`: Soft delete flag, allows disabling accounts without losing data
- `created_at`, `updated_at`: Timestamps inherited from `BaseModel`

**Relationships:**
- One-to-many with Scan: `user.scans` returns all scans created by this user
- Defined by relationship in Scan model: `user = relationship("User", backref="scans")`

### Scan Model

```python
# models/Scan.py:15-57
class Scan(BaseModel):
    """
    Stores metadata about scans performed on target URLs
    """
    __tablename__ = "scans"
    
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),  # Delete scans when user deleted
        nullable=False,
        index=True,
    )
    target_url = Column(
        String(settings.URL_MAX_LENGTH),  # 2048 chars
        nullable=False,
    )
    scan_date = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    
    user = relationship("User", backref="scans")
    test_results = relationship(
        "TestResult",
        back_populates="scan",
        cascade="all, delete-orphan",  # Delete results when scan deleted
    )
```

**Fields explained:**
- `user_id`: Foreign key to users table, indexed for filtering scans by user
- `target_url`: URL that was scanned, up to 2048 chars for long query strings
- `scan_date`: When scan was initiated, timezone-aware datetime in UTC
- `CASCADE`: When user is deleted, their scans are deleted. When scan is deleted, its test results are deleted

**Relationships:**
- Many-to-one with User: `scan.user` gets the user who created it
- One-to-many with TestResult: `scan.test_results` gets all vulnerability findings

**Properties** (computed, not stored):

```python
@property
def has_vulnerabilities(self) -> bool:
    return any(result.status == "vulnerable" for result in self.test_results)

@property
def vulnerability_count(self) -> int:
    return sum(1 for result in self.test_results if result.status == "vulnerable")
```

### TestResult Model

```python
# models/TestResult.py:16-57
class TestResult(BaseModel):
    """
    Stores individual test results for each security scan
    """
    __tablename__ = "test_results"
    
    scan_id = Column(
        Integer,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    test_name = Column(
        Enum(TestType),  # rate_limit, auth, sqli, idor
        nullable=False,
        index=True,
    )
    status = Column(
        Enum(ScanStatus),  # vulnerable, safe, error
        nullable=False,
        index=True,
    )
    severity = Column(
        Enum(Severity),  # critical, high, medium, low, info
        nullable=False,
        index=True,
    )
    details = Column(Text, nullable=False)
    evidence_json = Column(JSON, nullable=False, default=dict)
    recommendations_json = Column(JSON, nullable=False, default=list)
```

**Fields explained:**
- `scan_id`: Foreign key to scans table, which scan this result belongs to
- `test_name`: Enum constraining values to valid test types, indexed for filtering by test
- `status`: Enum for vulnerable/safe/error, indexed for finding all vulnerabilities
- `severity`: Enum for CRITICAL/HIGH/MEDIUM/LOW/INFO, indexed for prioritization
- `details`: Text description of what was found
- `evidence_json`: JSON storing response codes, payloads, timings - varies by test type
- `recommendations_json`: Array of strings with remediation steps

**Why JSON columns:**
Evidence varies by test type:
- Rate limit test: `{"rate_limit_headers": {...}, "bypass_method": "IP spoofing"}`
- SQLi test: `{"database_type": "mysql", "payload": "' OR 1=1--", "response_time": "5.23s"}`
- Auth test: `{"algorithm_variant": "none", "status_code": 200}`

JSON flexibility lets each scanner store relevant data without schema changes.

## Security Architecture

### Threat Model

What we're protecting against:

1. **Unauthorized access to scan data** - Users should only see their own scans. Attacker tries to view scan ID 123 when they only created scan ID 456. Defense: Authorization check in `services/scan_service.py:77-80` verifies `scan.user_id == user_id`.

2. **Token theft and replay** - Attacker steals JWT from network traffic or XSS. Defense: HTTPS in production (enforced by nginx), short token lifetime (24 hours from `config.py:24`), httpOnly cookies (not implemented but recommended).

3. **Brute force login attempts** - Attacker tries common passwords against accounts. Defense: Rate limiting at `routes/auth.py:49` limits login to 20/minute, bcrypt makes password verification slow.

4. **SQL injection in scanner payloads** - Malicious user creates scan with SQLi payload as target URL hoping to exploit our database. Defense: All database access uses parameterized queries via SQLAlchemy, never concatenation.

5. **Resource exhaustion** - Attacker submits scans with max_requests=50 repeatedly to consume backend resources. Defense: Rate limiting on scan creation (15/minute), timeout limits on scanners, max_requests capped at 50.

What we're NOT protecting against (out of scope):

- **DDoS attacks** - Application-level rate limiting can't stop volumetric network floods. Requires infrastructure defenses (CloudFlare, AWS Shield).
- **Database compromise** - If attacker gains direct database access, they can read all data. Requires infrastructure hardening, encrypted columns for sensitive data.
- **Server-side request forgery (SSRF)** - Scanners make requests to user-provided URLs. This is intentional functionality. Mitigation: scanners run with limited network access, not on internal network.

### Defense Layers

Multiple layers of security create defense in depth:

```
Layer 1: Network (Nginx)
    ↓ HTTPS, CORS headers, rate limits
Layer 2: Application (FastAPI)
    ↓ JWT validation, endpoint rate limits, input validation
Layer 3: Business Logic (Services)
    ↓ Authorization checks, transaction management
Layer 4: Data Access (Repositories)
    ↓ Parameterized queries, row-level permissions
```

**Why multiple layers?**
If one defense fails, others catch the attack. Example: Nginx rate limit bypassed via IP spoofing, but application-level rate limit (by user ID) still protects. JWT validation bypassed somehow, but service layer still checks `scan.user_id` before returning data.

### Authentication Flow

Complete JWT authentication cycle:

**1. Registration** (`services/auth_service.py:19-41`):
```python
# Hash password with bcrypt
hashed_password = hash_password(user_data.password)
# Bcrypt automatically generates salt, 10 rounds by default

# Store hashed password
user = UserRepository.create_user(
    db=db,
    email=user_data.email,
    hashed_password=hashed_password,
)
```

**2. Login** (`services/auth_service.py:43-71`):
```python
# Verify password
if not verify_password(login_data.password, user.hashed_password):
    raise HTTPException(status_code=401, detail="Invalid email or password")

# Create JWT with expiration
access_token = create_access_token(
    data={"sub": user.email},  # Subject claim
    expires_delta=timedelta(minutes=1440)  # 24 hours
)

return TokenResponse(access_token=access_token, token_type="bearer")
```

**3. Protected endpoint access** (`core/dependencies.py:17-49`):
```python
# Extract token from Authorization header
credentials: HTTPAuthorizationCredentials = Depends(security)
# security = HTTPBearer() from fastapi.security

# Decode and verify token
payload = decode_token(credentials.credentials)
email = payload.get("sub")

# Load user from database
user = UserRepository.get_by_email(db, email)
if not user:
    raise HTTPException(status_code=401)

return UserResponse.model_validate(user)
```

**4. Route handler receives authenticated user**:
```python
@router.post("/scans/")
async def create_scan(
    current_user: UserResponse = Depends(get_current_user),  # Authenticated
    ...
):
    # current_user is guaranteed to be valid at this point
    return ScanService.run_scan(db, current_user.id, ...)
```

### Rate Limiting Strategy

Multiple rate limit implementations:

**1. Nginx level** - Not implemented in dev, but production nginx can use limit_req:
```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;
limit_req zone=api_limit burst=20 nodelay;
```

**2. Application level** - SlowAPI per-endpoint limits (`backend/factory.py:34-36`):
```python
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

Applied to routes:
```python
# routes/auth.py:25-28
@router.post("/register", ...)
@limiter.limit(settings.API_RATE_LIMIT_REGISTER)  # "15/minute"
async def register(...):

# routes/auth.py:47-50
@router.post("/login", ...)
@limiter.limit(settings.API_RATE_LIMIT_LOGIN)  # "20/minute"
async def login(...):

# routes/scans.py:23-26
@router.post("/", ...)
@limiter.limit(settings.API_RATE_LIMIT_SCAN)  # "15/minute"
async def create_scan(...):
```

**3. Scanner-level** - Outgoing requests to targets are spaced (`base_scanner.py:64-90`):
```python
def _wait_before_request(self, jitter_ms: int | None = None) -> None:
    """
    Implement request spacing to avoid overwhelming target
    """
    required_delay = 1.0 / (self.max_requests / settings.SCANNER_RATE_LIMIT_WINDOW_SECONDS)
    # If max_requests=100 and window=60s, delay = 1.0 / (100/60) = 0.6s between requests
    
    jitter = random.uniform(0, jitter_ms / 1000.0)  # Random variation
    elapsed = time.time() - self.last_request_time
    
    if elapsed < required_delay:
        time.sleep(required_delay - elapsed + jitter)
```

This prevents scanners from hammering target APIs and getting IP banned.

## Storage Strategy

### PostgreSQL

**What we store:**
- User accounts (email, hashed password)
- Scan metadata (target URL, timestamp)
- Test results (findings, evidence, recommendations)

**Why PostgreSQL:**
- Relational data with foreign keys (scans → users, test_results → scans)
- JSON column support for flexible evidence storage
- ACID transactions for data integrity
- Mature, well-documented, widely deployed

Alternatives considered:
- MongoDB: Better for schema-less data, but we have clear relationships and benefit from foreign key constraints
- SQLite: Simpler setup, but doesn't handle concurrent writes well (multiple scans running simultaneously)

**Schema design:**

```sql
-- Automatically generated by SQLAlchemy from models
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX ix_users_email ON users(email);

CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_url VARCHAR(2048) NOT NULL,
    scan_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX ix_scans_user_id ON scans(user_id);

CREATE TABLE test_results (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    test_name VARCHAR NOT NULL,  -- Enum: rate_limit, auth, sqli, idor
    status VARCHAR NOT NULL,      -- Enum: vulnerable, safe, error
    severity VARCHAR NOT NULL,    -- Enum: critical, high, medium, low, info
    details TEXT NOT NULL,
    evidence_json JSON NOT NULL,
    recommendations_json JSON NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX ix_test_results_scan_id ON test_results(scan_id);
CREATE INDEX ix_test_results_test_name ON test_results(test_name);
CREATE INDEX ix_test_results_status ON test_results(status);
CREATE INDEX ix_test_results_severity ON test_results(severity);
```

**Indexes explained:**
- `users.email`: Fast login lookups (WHERE email = ?)
- `scans.user_id`: Fast filtering (WHERE user_id = ?)
- `test_results.scan_id`: Fast joins (JOIN scans WHERE scan_id = ?)
- `test_results.status`: Fast vulnerability queries (WHERE status = 'vulnerable')
- `test_results.severity`: Fast filtering by severity (WHERE severity = 'critical')

### Connection Pooling

Database connections are expensive to create. SQLAlchemy maintains a pool:

```python
# core/database.py:12-17
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Verify connections before use (handles DB restarts)
    echo=settings.DEBUG,  # Log all SQL when DEBUG=True
)
```

Default pool size: 5 connections, overflow: 10 (up to 15 total).

Session lifecycle managed by dependency:

```python
# core/database.py:28-36
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for database sessions
    """
    db = SessionLocal()
    try:
        yield db  # Provide to route handler
    finally:
        db.close()  # Always close, even if exception
```

## Configuration

### Environment Variables

All configuration lives in `.env` and `config.py`:

```python
# config.py:14-69
class Settings(BaseSettings):
    # Application
    APP_NAME: str = "API Security Tester"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str  # Required, no default
    
    # Security - JWT
    SECRET_KEY: str  # Required, MUST be random in production
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    # Rate limiting
    API_RATE_LIMIT_LOGIN: str = "20/minute"
    API_RATE_LIMIT_REGISTER: str = "15/minute"
    API_RATE_LIMIT_SCAN: str = "15/minute"
    
    # Scanner limits
    SCANNER_MAX_CONCURRENT_REQUESTS: int = 50
    SCANNER_CONNECTION_TIMEOUT: int = 180
    DEFAULT_MAX_REQUESTS: int = 100
```

**Why centralized config:**
- Single source of truth for all constants
- Type validation with Pydantic
- Easy to change without touching code
- Different values for dev/test/prod

**Configuration strategy:**
Development uses `.env` file loaded by Docker Compose. Production uses environment variables set directly in Docker, Kubernetes, or cloud platform.

Critical settings that must be changed for production:
- `SECRET_KEY` - Generate with `openssl rand -hex 32`
- `DEBUG` - Must be `false`
- `DATABASE_URL` - Production database, not localhost
- `CORS_ORIGINS` - Actual frontend domain, not `http://localhost`

## Performance Considerations

### Bottlenecks

Where this system gets slow under load:

1. **Scanner HTTP requests** - Each scan makes 10-100 HTTP requests to external APIs. If target is slow (5s response time), scans take minutes. Can't parallelize much without overwhelming targets. Mitigated by timeout limits (180s from `config.py:51`).

2. **Database queries with relationships** - Loading `scan.test_results` triggers N+1 queries if not eager loaded. With 10 scans and 4 results each = 41 queries (1 for scans + 40 for results). Solved with `joinedload()` in repositories:

```python
# repositories/scan_repository.py:50-59
return (
    db.query(Scan)
    .options(joinedload(Scan.test_results))  # Single query with JOIN
    .filter(Scan.user_id == user_id)
    .all()
)
```

3. **Password hashing on login** - Bcrypt is intentionally slow (prevents brute force). Each login takes ~100ms. Under load, authentication becomes bottleneck. Mitigated by rate limiting login attempts and using caching (not implemented, but could add Redis for session tokens).

### Optimizations

What we did to make it faster:

- **Request pooling** - `BaseScanner` reuses `requests.Session()` which maintains connection pools to targets. Avoids TCP handshake overhead on each request.

- **Database indexes** - Foreign keys and commonly queried columns (email, user_id, status) are indexed. Queries that would do table scans become index lookups.

- **Response pagination** - Scan list queries use LIMIT/OFFSET to avoid loading thousands of records:

```python
# repositories/scan_repository.py:50-71
@staticmethod
def get_by_user(
    db: Session,
    user_id: int,
    skip: int = 0,
    limit: int | None = None  # Default 100 from config
) -> list[Scan]:
    if limit is None:
        limit = settings.DEFAULT_PAGINATION_LIMIT
    
    return (
        db.query(Scan)
        .offset(skip)
        .limit(limit)  # Only load requested page
        .all()
    )
```

- **Enum columns** - `test_name`, `status`, `severity` use Postgres ENUMs, not strings. Smaller storage, faster comparisons, enforced validity.

### Scalability

**Vertical scaling** (more CPU/RAM on single server):
- Database: Increase `max_connections` in Postgres config
- Backend: Run more gunicorn workers (4 workers in production Dockerfile)
- Frontend: Nginx already efficient, bottleneck is unlikely here

Current limits with single server:
- Database can handle ~100 concurrent connections
- Backend with 4 workers handles ~400 concurrent requests
- Scanners are the real limit - each scan is long-running (30-60s)

**Horizontal scaling** (more servers):
Challenges:
- Scanners are stateless, can run on any backend instance ✓
- Database requires connection pooling strategy (PgBouncer)
- Shared session state needed (Redis) or stick to JWT (stateless) ✓
- Load balancer required (nginx, AWS ALB)

What needs to change:
- Add load balancer in front of backend
- Configure shared session store or rely solely on JWT
- Database connection pool management (PgBouncer)
- Consider async task queue (Celery, RQ) for long-running scans

## Design Decisions

### Decision 1: Synchronous scanners despite FastAPI async

**What we chose:**
Scanners use synchronous `requests` library, not async `httpx` or `aiohttp`.

**Alternatives considered:**
- `httpx` async HTTP client - Could run all tests concurrently
- `aiohttp` - Similar benefits, different API

**Trade-offs:**
Pros of sync:
- Simpler code, easier to reason about timing
- Time-based SQLi detection requires precise timing control
- Baseline timing calculation needs sequential requests
- Standard `requests` library is battle-tested

Cons of sync:
- Can't run multiple tests concurrently within a scan
- Blocks event loop (mitigated by running in thread pool)
- Slower for scans with many tests

**Why we made this choice:**
Accuracy over speed. Time-based blind SQL injection detection (`sqli_scanner.py:183-251`) requires:
1. Establish baseline response time (multiple samples)
2. Send delay payload
3. Measure if response is slower by expected amount

Async concurrency would introduce timing noise. A delay of 5.1s vs 5.3s could be network jitter, not SQLi. Sequential requests with controlled spacing give cleaner signals.

### Decision 2: Repository pattern over Active Record

**What we chose:**
Repository pattern - `UserRepository.get_by_email(db, email)` instead of `User.find_by_email(email)`.

**Alternatives considered:**
- Active Record (Django-style) - Models have class methods for queries
- Data Mapper (raw SQL) - Write SQL strings directly

**Trade-offs:**
Pros of repository:
- Clear separation: models define structure, repositories define queries
- Testable: mock repositories in unit tests
- Flexible: swap ORM without changing service code

Cons of repository:
- More files, more navigation
- Extra abstraction layer
- Can feel like overkill for simple CRUD

**Why we made this choice:**
Testability and maintainability. Services like `AuthService.login_user()` call `UserRepository.get_by_email()`. In tests, mock the repository to return a fake user without touching the database.

If we later migrate from SQLAlchemy to another ORM, we only change repository implementations. Services remain unchanged.

### Decision 3: JWT without refresh tokens

**What we chose:**
Single long-lived JWT (24 hours), no refresh token mechanism.

**Alternatives considered:**
- Short access tokens (15 min) + refresh tokens (30 days)
- Session-based auth with server-side storage

**Trade-offs:**
Pros of current approach:
- Simpler implementation, no refresh endpoint
- Stateless - no session storage needed
- Works across multiple backend instances immediately

Cons of current approach:
- Can't invalidate tokens before expiration
- If token stolen, attacker has 24 hours of access
- No way to force logout on all devices

**Why we made this choice:**
Simplicity for educational project. Adding refresh tokens requires:
- Refresh token storage (database or Redis)
- Refresh endpoint with rotation logic
- Token revocation tracking
- More complex frontend token management

For a production app, you'd implement refresh tokens. For learning how JWT works, this is clearer.

### Decision 4: Docker Compose for local development

**What we chose:**
Run everything in Docker containers with `dev.compose.yml`, even for local development.

**Alternatives considered:**
- Local Postgres + local Python + local Node (no Docker)
- Docker for services, local for development
- Kubernetes locally (minikube, kind)

**Trade-offs:**
Pros of Docker Compose:
- Identical environment for all developers
- Spin up entire stack with one command
- Hot reload still works with volume mounts
- Production architecture matches dev (Docker in both)

Cons of Docker Compose:
- Slower file system on Mac (volume mounts)
- Extra resource usage (containers overhead)
- Learning curve for Docker debugging

**Why we made this choice:**
"Works on my machine" is eliminated. Every developer gets Postgres 16, Python 3.11, Node 20 regardless of their host OS. New team member runs `docker compose up` and they're ready.

Volume mounts preserve hot reload:
```yaml
# dev.compose.yml:33-35
volumes:
  - ./backend:/app  # Maps local backend/ to container /app
  # Changes to backend/*.py trigger uvicorn reload
```

## Deployment Architecture

Production deployment uses optimized containers:

```
                    ┌──────────────────┐
Internet ────────>  │  Nginx (Port 80) │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  Backend (8000)  │
                    │  Gunicorn        │
                    │  4 workers       │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  PostgreSQL      │
                    │  (internal only) │
                    └──────────────────┘
```

**Components:**

**Nginx container** - Built from `conf/docker/prod/vite.docker`:
- Multi-stage build: compile React, then serve with nginx
- Serves static files from `/usr/share/nginx/html`
- Proxies `/api` to backend
- Gzip compression, caching headers

**Backend container** - Built from `conf/docker/prod/fastapi.docker`:
- Runs gunicorn with 4 uvicorn workers
- Non-root user for security
- No volume mounts (code baked into image)

**Database container** - Postgres 16 Alpine:
- Not exposed to host in production
- Data persists in Docker volume

**Infrastructure:**
Minimal production setup:
- Single VPS (DigitalOcean Droplet, AWS EC2)
- Docker Compose orchestration
- SSL via Let's Encrypt (certbot) or Cloudflare proxy

Scaling beyond single server:
- Backend: Multiple instances behind load balancer
- Database: Read replicas, connection pooling
- Static files: CDN (CloudFront, Cloudflare)

## Error Handling Strategy

### Error Types

1. **Validation errors** (400) - Pydantic catches bad input:
```python
# schemas/user_schemas.py:26-38
@field_validator("password")
@classmethod
def validate_password_strength(cls, v: str) -> str:
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain uppercase letter")
    # Pydantic converts to HTTP 422 automatically
```

2. **Authentication errors** (401) - JWT invalid or expired:
```python
# core/dependencies.py:33-36
if email is None:
    raise HTTPException(
        status_code=401,
        detail="Invalid authentication credentials"
    )
```

3. **Authorization errors** (403) - Valid user, wrong resource:
```python
# services/scan_service.py:77-80
if scan.user_id != user_id:
    raise HTTPException(
        status_code=403,
        detail="Not authorized to access this scan"
    )
```

4. **Not found errors** (404) - Resource doesn't exist:
```python
# services/scan_service.py:73-74
if not scan:
    raise HTTPException(status_code=404, detail="Scan not found")
```

5. **Scanner errors** - Caught and returned as `status="error"`:
```python
# services/scan_service.py:52-65
try:
    scanner = scanner_class(...)
    result = scanner.scan()
    results.append(result)
except Exception as e:
    results.append(
        TestResultCreate(
            test_name=test_type,
            status="error",
            severity="info",
            details=f"Scanner error: {str(e)}",
            ...
        )
    )
```

### Recovery Mechanisms

**Database connection loss:**
- Detection: `pool_pre_ping=True` tests connections before use
- Response: SQLAlchemy automatically reconnects
- Recovery: Failed transaction rolls back, next request gets new connection

**Scanner timeout:**
- Detection: `requests.Timeout` exception after `SCANNER_CONNECTION_TIMEOUT` seconds
- Response: Retry with exponential backoff (up to 3 times)
- Recovery: If all retries fail, return error result (scan continues with other tests)

**Rate limit exceeded (429 from target):**
- Detection: HTTP 429 status code in scanner response
- Response: Read `Retry-After` header, wait specified duration
- Recovery: Retry request after waiting

Code from `base_scanner.py:92-156`:
```python
def make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
    retry_count = 0
    backoff_factor = 2.0
    
    while retry_count <= settings.DEFAULT_RETRY_COUNT:
        try:
            response = self.session.request(method, url, **kwargs)
            
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                wait_time = int(retry_after) if retry_after.isdigit() else 60
                time.sleep(wait_time)
                retry_count += 1
                continue  # Try again
            
            if response.status_code >= 500:  # Server error
                wait_time = backoff_factor ** retry_count
                time.sleep(wait_time)
                retry_count += 1
                continue
            
            return response  # Success
        
        except (requests.Timeout, requests.ConnectionError):
            if retry_count < settings.DEFAULT_RETRY_COUNT:
                wait_time = backoff_factor ** retry_count
                time.sleep(wait_time)
                retry_count += 1
            else:
                raise  # Give up after retries exhausted
```

## Extensibility

### Where to Add Features

Want to add a new security test (e.g., XSS detection)? Here's the process:

**1. Create scanner** in `backend/scanners/xss_scanner.py`:
```python
from .base_scanner import BaseScanner
from core.enums import TestType, ScanStatus, Severity

class XSSScanner(BaseScanner):
    def scan(self) -> TestResultCreate:
        # Test for reflected XSS
        test_result = self._test_reflected_xss()
        
        if test_result["vulnerable"]:
            return TestResultCreate(
                test_name=TestType.XSS,  # Need to add to enum
                status=ScanStatus.VULNERABLE,
                severity=Severity.HIGH,
                details="Reflected XSS detected",
                evidence_json=test_result,
                recommendations_json=[...]
            )
        
        return TestResultCreate(test_name=TestType.XSS, status=ScanStatus.SAFE, ...)
```

**2. Add to enum** in `backend/core/enums.py:19-25`:
```python
class TestType(str, Enum):
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    SQLI = "sqli"
    IDOR = "idor"
    XSS = "xss"  # New test type
```

**3. Register in service** at `backend/services/scan_service.py:32-37`:
```python
scanner_mapping: dict[TestType, type[BaseScanner]] = {
    TestType.RATE_LIMIT: RateLimitScanner,
    TestType.AUTH: AuthScanner,
    TestType.SQLI: SQLiScanner,
    TestType.IDOR: IDORScanner,
    TestType.XSS: XSSScanner,  # Register new scanner
}
```

**4. Update frontend constants** in `frontend/src/config/constants.ts:44-51`:
```typescript
export const SCAN_TEST_TYPES = {
  RATE_LIMIT: 'rate_limit',
  AUTH: 'auth',
  SQLI: 'sqli',
  IDOR: 'idor',
  XSS: 'xss',  // Add new test type
} as const;

export const TEST_TYPE_LABELS: Record<ScanTestType, string> = {
  // ... existing
  [SCAN_TEST_TYPES.XSS]: 'Cross-Site Scripting',
};
```

No changes needed to:
- Database schema (test_name is enum, migrations auto-update)
- Routes (they just pass through test types)
- Repositories (they store whatever test types are sent)

## Limitations

Current architectural limitations:

1. **No scan queueing** - Scans run synchronously in request handler. If 10 users submit scans simultaneously, they all block on scanner HTTP requests. Fix requires async task queue (Celery with Redis, or RQ).

2. **No real-time scan progress** - Frontend submits scan and waits for complete response. Long scans (2 minutes) show no progress. Fix requires WebSocket connection or polling for progress updates.

3. **Single target per scan** - Can't scan multiple URLs in one operation. Fix requires loop in service layer and UI for multiple target inputs.

4. **No historical comparison** - Can't compare scan results over time ("Was this vulnerable last week?"). Fix requires additional queries and UI for trend visualization.

5. **Limited concurrency in scanners** - Tests run sequentially within a scan. Could run all 4 tests simultaneously, but chose not to for timing accuracy. Trade-off between speed and precision.

These are not bugs - they're conscious trade-offs. Fixing them would require significant architectural changes.

## Comparison to Similar Systems

### Burp Suite

How we're different:
- Burp is a proxy, we're a standalone scanner
- Burp has GUI desktop app, we're web-based
- Burp is comprehensive (hundreds of tests), we focus on 4 core vulnerabilities

Why we made different choices:
Educational focus. Burp is for professional pentesters. This project teaches how scanners work by implementing the core logic yourself.

### OWASP ZAP

How we're different:
- ZAP is passive + active scanning, we're active only
- ZAP auto-discovers endpoints, we test provided URLs
- ZAP integrates with CI/CD, we're standalone

Why we made different choices:
Simplicity. ZAP is powerful but complex. This project shows the fundamentals without overwhelming features.

## Evolution

### Version 1.0 Design (Current)

Initial design focused on:
- Four core vulnerability types
- Synchronous scanners for accuracy
- Repository pattern for clean separation
- Docker-first development

### Future Improvements

Planned architectural changes:

1. **Async task queue** - Move scanning to background workers
   - Why: Non-blocking API, better scalability
   - What it enables: Real-time progress, scheduled scans

2. **Plugin system** - Load scanners dynamically
   - Why: Extensibility without modifying core
   - What it enables: Community contributions, custom tests

3. **Report generation** - PDF/HTML export of results
   - Why: Sharing findings with teams
   - What it enables: Professional documentation

4. **Webhook notifications** - Alert when scans complete
   - Why: Integration with other tools
   - What it enables: Slack/email notifications, CI/CD integration

## Key Files Reference

Quick map of where to find things:

- `backend/factory.py` - Application factory, middleware setup, route registration
- `backend/config.py` - All environment variables and configuration
- `backend/core/database.py` - Database engine and session management
- `backend/core/security.py` - JWT creation, password hashing, token validation
- `backend/core/dependencies.py` - FastAPI dependencies (auth, database)
- `backend/models/` - SQLAlchemy models (User, Scan, TestResult)
- `backend/repositories/` - Database query functions
- `backend/services/` - Business logic orchestration
- `backend/routes/` - API endpoints
- `backend/scanners/base_scanner.py` - Common scanner functionality
- `backend/scanners/*_scanner.py` - Individual vulnerability tests
- `frontend/src/hooks/` - React Query hooks for API calls
- `frontend/src/services/` - API client functions
- `frontend/src/store/` - Zustand state management
- `conf/nginx/` - Nginx reverse proxy configuration
- `compose.yml` - Production Docker Compose
- `dev.compose.yml` - Development with volume mounts

## Next Steps

Now that you understand the architecture:

1. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) for code walkthrough - see how each scanner detects vulnerabilities, how authentication flows work, and how data moves through the layers
2. Try modifying scanners - change SQLi payloads, adjust timing thresholds, add new detection logic to understand the implementation details
