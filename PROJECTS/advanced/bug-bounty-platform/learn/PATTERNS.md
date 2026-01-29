# Design Patterns Explained

This document explains the key design patterns used in the Bug Bounty Platform, why they were chosen, and how they improve code quality.

---

## Table of Contents

1. [Dependency Injection](#dependency-injection)
2. [Repository Pattern](#repository-pattern)
3. [Layered Architecture](#layered-architecture)
4. [Factory Pattern](#factory-pattern)
5. [Strategy Pattern](#strategy-pattern)
6. [Singleton Pattern](#singleton-pattern)
7. [Mixin Pattern](#mixin-pattern)
8. [Observer Pattern (Pub/Sub)](#observer-pattern-pubsub)

---

## Dependency Injection

**What it is:** Instead of creating dependencies inside a class, they are "injected" from outside.

**Without Dependency Injection:**

```python
class UserService:
    def __init__(self):
        self.db = Database()  # Hardcoded dependency
        self.cache = Redis()  # Hardcoded dependency

    def get_user(self, user_id: str):
        cached = self.cache.get(f"user:{user_id}")
        if cached:
            return cached
        user = self.db.query(f"SELECT * FROM users WHERE id = '{user_id}'")
        self.cache.set(f"user:{user_id}", user)
        return user
```

Problems:
- Hard to test (can't mock Database or Redis)
- Tight coupling (UserService depends on specific implementations)
- Can't swap implementations (e.g., use a different cache)

**With Dependency Injection:**

```python
class UserService:
    def __init__(self, db: Database, cache: Cache):
        self.db = db      # Injected from outside
        self.cache = cache # Injected from outside

    def get_user(self, user_id: str):
        cached = self.cache.get(f"user:{user_id}")
        if cached:
            return cached
        user = self.db.query(f"SELECT * FROM users WHERE id = '{user_id}'")
        self.cache.set(f"user:{user_id}", user)
        return user

# Usage
db = Database()
cache = Redis()
user_service = UserService(db=db, cache=cache)
```

Benefits:
- Easy to test (inject mocks)
- Loose coupling (depends on interfaces, not implementations)
- Flexible (can inject different implementations)

### Dependency Injection in FastAPI

FastAPI has built-in DI using `Depends()`:

```python
from fastapi import Depends
from typing import Annotated

# Dependency function
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with DatabaseSessionManager().session() as session:
        yield session

# Type alias for convenience
DatabaseSession = Annotated[AsyncSession, Depends(get_db_session)]

# Route using dependency
@router.get("/users/{user_id}")
async def get_user(
    user_id: UUID,
    session: DatabaseSession,  # ← Automatically injected
) -> UserResponse:
    repo = UserRepository(session)
    user = await repo.get_by_id(user_id)
    return user
```

**How it works:**
1. FastAPI sees `session: DatabaseSession` parameter
2. Recognizes `DatabaseSession` is an `Annotated` type with `Depends()`
3. Calls `get_db_session()` to get a session
4. Injects the session into the route handler
5. Automatically cleans up when request finishes

**Real example from the codebase:**

```python
# backend/app/core/dependencies.py

async def get_current_user(
    token: str = Header(...),
    session: DatabaseSession,
) -> User:
    payload = decode_access_token(token)
    user_id = payload["sub"]
    repo = UserRepository(session)
    user = await repo.get_by_id(user_id)
    if not user:
        raise UnauthorizedError()
    return user

# Type alias
CurrentUser = Annotated[User, Depends(get_current_user)]

# Usage in routes
@router.get("/me")
async def get_me(user: CurrentUser) -> UserResponse:
    return user  # User is automatically injected and authenticated!
```

**Why this is powerful:**
- Route handlers don't need to worry about authentication
- DRY principle (don't repeat auth logic in every route)
- Easy to test (mock `get_current_user`)
- Composable (dependencies can depend on other dependencies)

---

## Repository Pattern

**What it is:** An abstraction layer between business logic and data storage.

**The problem:**

```python
# Business logic mixed with database queries
@router.post("/users")
async def create_user(data: UserCreate, session: DatabaseSession):
    # Database query in route handler
    stmt = select(User).where(User.email == data.email)
    result = await session.execute(stmt)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
    )
    session.add(user)
    await session.commit()
    return user
```

Problems:
- Route handler knows about database schema
- Hard to test (need to set up database)
- Can't switch databases easily
- Duplicate query logic across multiple routes

**The Repository Pattern solution:**

```python
# 1. Create a repository class
class UserRepository(BaseRepository[User]):
    async def find_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, data: UserCreate) -> User:
        user = User(
            email=data.email,
            password_hash=hash_password(data.password),
        )
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user

# 2. Use repository in route handler
@router.post("/users")
async def create_user(data: UserCreate, session: DatabaseSession):
    repo = UserRepository(session)

    existing_user = await repo.find_by_email(data.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    user = await repo.create(data)
    await session.commit()
    return user
```

Benefits:
- Route handler doesn't know about database schema
- Query logic is reusable
- Easy to test (mock repository)
- Can swap database implementation

### Generic Base Repository

To avoid repeating CRUD operations, we use a **generic base repository**:

```python
from typing import Generic, TypeVar

ModelT = TypeVar("ModelT", bound=Base)

class BaseRepository(Generic[ModelT]):
    def __init__(self, session: AsyncSession, model: type[ModelT]):
        self.session = session
        self.model = model

    async def get_by_id(self, id: UUID) -> ModelT | None:
        stmt = select(self.model).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_all(self, limit: int = 100, offset: int = 0) -> list[ModelT]:
        stmt = select(self.model).limit(limit).offset(offset)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, **kwargs) -> ModelT:
        instance = self.model(**kwargs)
        self.session.add(instance)
        await self.session.flush()
        await self.session.refresh(instance)
        return instance

    async def delete(self, id: UUID) -> None:
        stmt = delete(self.model).where(self.model.id == id)
        await self.session.execute(stmt)
```

**Usage:**

```python
# Specific repository extends base
class UserRepository(BaseRepository[User]):
    def __init__(self, session: AsyncSession):
        super().__init__(session, User)

    # Add domain-specific methods
    async def find_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

# Usage
repo = UserRepository(session)
user = await repo.get_by_id(user_id)      # From BaseRepository
user = await repo.find_by_email(email)    # From UserRepository
```

**Why generics?**
- Type safety: `repo.get_by_id()` returns `User`, not `Any`
- Reusable: All models get CRUD for free
- DRY: Write common operations once

---

## Layered Architecture

**What it is:** Organizing code into layers, where each layer has a specific responsibility.

```
┌─────────────────────────────────────┐
│         Presentation Layer          │  ← Routes (HTTP)
│  - Handle HTTP requests/responses   │
│  - Input validation                 │
│  - Serialize data to JSON           │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│          Business Layer             │  ← Services
│  - Core business logic              │
│  - Orchestrate repositories         │
│  - Transaction management           │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│         Data Access Layer           │  ← Repositories
│  - Database queries                 │
│  - CRUD operations                  │
│  - No business logic                │
└───────────────┬─────────────────────┘
                │
┌───────────────▼─────────────────────┐
│           Database                  │  ← PostgreSQL
└─────────────────────────────────────┘
```

**Rules:**
1. **Top-down dependency:** Upper layers depend on lower layers, never the reverse
2. **Single responsibility:** Each layer has one job
3. **No layer skipping:** Routes can't directly query the database

**Example: Creating a report**

```python
# 1. Presentation Layer (routes.py)
@router.post("/reports")
async def create_report(
    data: ReportCreate,
    user: CurrentUser,
    session: DatabaseSession,
) -> ReportResponse:
    report = await submit_vulnerability_report(
        session=session,
        author_id=user.id,
        data=data,
    )
    return ReportResponse.from_orm(report)
```

The route:
- Validates input (`ReportCreate` Pydantic model)
- Authenticates user (`CurrentUser` dependency)
- Calls service function
- Serializes output (`ReportResponse`)

```python
# 2. Business Layer (service.py)
async def submit_vulnerability_report(
    session: AsyncSession,
    author_id: UUID,
    data: ReportCreate,
) -> Report:
    # Validate program exists
    program_repo = ProgramRepository(session)
    program = await program_repo.get_by_slug(data.program_slug)
    if not program:
        raise ProgramNotFoundError()

    # Check if program accepts reports
    if program.status != ProgramStatus.ACTIVE:
        raise ProgramNotActiveError()

    # Create report
    report_repo = ReportRepository(session)
    report = await report_repo.create(
        author_id=author_id,
        program_id=program.id,
        title=data.title,
        description=data.description,
        severity=data.severity,
    )

    # Send notification (in real app)
    # await notify_program_owner(program.owner_id, report.id)

    await session.commit()
    return report
```

The service:
- Implements business rules (program must be active)
- Coordinates multiple repositories (Program + Report)
- Manages transactions (commit)
- Throws domain exceptions

```python
# 3. Data Access Layer (repository.py)
class ReportRepository(BaseRepository[Report]):
    async def create(
        self,
        author_id: UUID,
        program_id: UUID,
        title: str,
        description: str,
        severity: Severity,
    ) -> Report:
        report = Report(
            author_id=author_id,
            program_id=program_id,
            title=title,
            description=description,
            severity=severity,
            status=ReportStatus.NEW,
        )
        self.session.add(report)
        await self.session.flush()
        await self.session.refresh(report)
        return report
```

The repository:
- Builds the Report model
- Adds to session
- Returns the instance
- No business logic

**Benefits:**
- **Testability:** Mock each layer independently
- **Maintainability:** Change one layer without affecting others
- **Scalability:** Extract layers to separate services if needed
- **Clarity:** Easy to find where logic lives

---

## Factory Pattern

**What it is:** A function/class that creates objects without specifying their exact class.

**Real example from the codebase:**

```python
# backend/app/factory.py

def create_app() -> FastAPI:
    app = FastAPI(
        title="Bug Bounty Platform",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

    # Register routers
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(user_router, prefix="/api/v1/users", tags=["users"])
    app.include_router(program_router, prefix="/api/v1/programs", tags=["programs"])
    app.include_router(report_router, prefix="/api/v1/reports", tags=["reports"])
    app.include_router(admin_router, prefix="/api/v1/admin", tags=["admin"])

    return app

# Usage
app = create_app()
```

**Benefits:**
- Centralized configuration
- Easy to create multiple app instances (testing, different environments)
- Follows Single Responsibility Principle

**Another example: Database session factory**

```python
class DatabaseSessionManager:
    def __init__(self):
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker | None = None

    def init(self, database_url: str):
        self._engine = create_async_engine(
            database_url,
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            pool_timeout=settings.DB_POOL_TIMEOUT,
            pool_recycle=settings.DB_POOL_RECYCLE,
        )
        self._sessionmaker = async_sessionmaker(
            self._engine,
            expire_on_commit=False,
        )

    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        if self._sessionmaker is None:
            raise DatabaseNotInitializedError()

        async with self._sessionmaker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

# Usage
db_manager = DatabaseSessionManager()
db_manager.init(settings.DATABASE_URL)

async with db_manager.session() as session:
    # Use session
    pass
```

---

## Strategy Pattern

**What it is:** Define a family of algorithms, encapsulate each one, and make them interchangeable.

**Example: Password hashing**

```python
from abc import ABC, abstractmethod

# Strategy interface
class PasswordHasher(ABC):
    @abstractmethod
    def hash(self, password: str) -> str:
        pass

    @abstractmethod
    def verify(self, password: str, hash: str) -> bool:
        pass

# Concrete strategies
class Argon2Hasher(PasswordHasher):
    def hash(self, password: str) -> str:
        return argon2.hash(password)

    def verify(self, password: str, hash: str) -> bool:
        try:
            return argon2.verify(hash, password)
        except Exception:
            return False

class BcryptHasher(PasswordHasher):
    def hash(self, password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def verify(self, password: str, hash: str) -> bool:
        return bcrypt.checkpw(password.encode(), hash.encode())

# Context
class PasswordService:
    def __init__(self, hasher: PasswordHasher):
        self.hasher = hasher

    def hash_password(self, password: str) -> str:
        return self.hasher.hash(password)

    def verify_password(self, password: str, hash: str) -> bool:
        return self.hasher.verify(password, hash)

# Usage
service = PasswordService(Argon2Hasher())  # Can swap to BcryptHasher()
hash = service.hash_password("secret123")
is_valid = service.verify_password("secret123", hash)
```

**Benefits:**
- Easy to add new algorithms (e.g., PBKDF2)
- Can switch algorithms without changing code
- Each strategy is independently testable

---

## Singleton Pattern

**What it is:** Ensure a class has only one instance and provide a global access point.

**Example: Database session manager**

```python
class DatabaseSessionManager:
    _instance: "DatabaseSessionManager | None" = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._engine = None
            cls._instance._sessionmaker = None
        return cls._instance

    def init(self, database_url: str):
        if self._engine is not None:
            return  # Already initialized

        self._engine = create_async_engine(database_url)
        self._sessionmaker = async_sessionmaker(self._engine)

    async def session(self):
        async with self._sessionmaker() as session:
            yield session

# Usage - always returns the same instance
db1 = DatabaseSessionManager()
db2 = DatabaseSessionManager()
assert db1 is db2  # True
```

**When to use:**
- Database connections (expensive to create)
- Loggers (single logging configuration)
- Configuration (load once, use everywhere)

**When NOT to use:**
- Most other cases (singletons are global state = hard to test)

---

## Mixin Pattern

**What it is:** A class that provides methods to other classes but isn't meant to be instantiated itself.

**Real example from the codebase:**

```python
# backend/app/core/Base.py

class UUIDMixin:
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid7,
    )

class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=func.now(),
        onupdate=func.now(),
    )

class SoftDeleteMixin:
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

# Usage: Compose mixins
class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))

class Report(Base, UUIDMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "reports"

    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
```

**Benefits:**
- DRY: Don't repeat `id`, `created_at`, `updated_at` in every model
- Composable: Mix and match (User doesn't need SoftDeleteMixin)
- Maintainable: Change `UUIDMixin` → all models updated

---

## Observer Pattern (Pub/Sub)

**What it is:** When an object changes state, all its dependents are notified automatically.

**Example: Event system**

```python
from typing import Callable

class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = {}

    def subscribe(self, event: str, handler: Callable):
        if event not in self._subscribers:
            self._subscribers[event] = []
        self._subscribers[event].append(handler)

    async def publish(self, event: str, data: dict):
        if event not in self._subscribers:
            return

        for handler in self._subscribers[event]:
            await handler(data)

# Event handlers
async def send_email_notification(data: dict):
    print(f"Sending email to {data['email']}")

async def log_event(data: dict):
    print(f"Logging event: {data}")

# Setup
bus = EventBus()
bus.subscribe("user.registered", send_email_notification)
bus.subscribe("user.registered", log_event)

# Trigger event
await bus.publish("user.registered", {
    "email": "user@example.com",
    "user_id": "123",
})
```

**Real-world use case:**

```python
# When a report is submitted
async def submit_report(...):
    report = await report_repo.create(...)

    # Publish event
    await event_bus.publish("report.submitted", {
        "report_id": report.id,
        "program_id": report.program_id,
        "author_id": report.author_id,
    })

    return report

# Multiple handlers react to the event
bus.subscribe("report.submitted", notify_program_owner)
bus.subscribe("report.submitted", update_analytics)
bus.subscribe("report.submitted", log_submission)
```

**Benefits:**
- Decoupled: Report submission doesn't know about notifications
- Extensible: Add new handlers without modifying code
- Testable: Can test each handler independently

---

## Combining Patterns

Real-world code often combines multiple patterns:

```python
# Dependency Injection + Repository + Layered Architecture

# 1. Route (Presentation Layer)
@router.post("/users")
async def create_user(
    data: UserCreate,
    session: DatabaseSession,  # Dependency Injection
) -> UserResponse:
    user = await register_user(session, data)  # Service Layer
    return UserResponse.from_orm(user)

# 2. Service (Business Layer)
async def register_user(
    session: AsyncSession,
    data: UserCreate,
) -> User:
    repo = UserRepository(session)  # Repository Pattern

    existing_user = await repo.find_by_email(data.email)
    if existing_user:
        raise UserAlreadyExistsError()

    password_hash = hash_password(data.password)  # Strategy Pattern
    user = await repo.create(
        email=data.email,
        password_hash=password_hash,
    )

    await session.commit()

    await event_bus.publish("user.registered", {  # Observer Pattern
        "user_id": user.id,
        "email": user.email,
    })

    return user

# 3. Repository (Data Access Layer)
class UserRepository(BaseRepository[User]):  # Generic Pattern
    async def find_by_email(self, email: str) -> User | None:
        ...

    async def create(self, **kwargs) -> User:
        ...
```

This combines:
- Dependency Injection (session injected)
- Repository Pattern (data access abstraction)
- Layered Architecture (route → service → repository)
- Strategy Pattern (hash_password can use different algorithms)
- Observer Pattern (event_bus.publish)
- Generic Pattern (BaseRepository[User])

---

## Conclusion

Design patterns are not about memorization, but about recognizing common problems and applying proven solutions.

**Key takeaways:**
1. **Dependency Injection** - Inject dependencies, don't hardcode them
2. **Repository Pattern** - Abstract data access from business logic
3. **Layered Architecture** - Separate presentation, business, and data layers
4. **Factory Pattern** - Centralize object creation
5. **Strategy Pattern** - Make algorithms interchangeable
6. **Singleton Pattern** - One instance for expensive resources
7. **Mixin Pattern** - Compose behavior from reusable pieces
8. **Observer Pattern** - Decouple event producers from consumers

For more information:
- System architecture: [ARCHITECTURE.md](./ARCHITECTURE.md)
- Database design: [DATABASE.md](./DATABASE.md)
- Security implementation: [SECURITY.md](./SECURITY.md)
- Hands-on tutorial: [GETTING-STARTED.md](./GETTING-STARTED.md)
