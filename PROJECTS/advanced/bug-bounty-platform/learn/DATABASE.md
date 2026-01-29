# Database Design Deep Dive

This document explains the database schema, design decisions, relationships, and migration strategies used in the Bug Bounty Platform.

---

## Table of Contents

1. [Schema Overview](#schema-overview)
2. [Entity Relationship Diagram](#entity-relationship-diagram)
3. [Table Schemas](#table-schemas)
4. [Design Decisions](#design-decisions)
5. [Indexes and Performance](#indexes-and-performance)
6. [Migrations](#migrations)
7. [Common Queries](#common-queries)

---

## Schema Overview

The platform uses **PostgreSQL 18** with 9 main tables:

| Table | Description | Rows (typical) |
|-------|-------------|----------------|
| `users` | User accounts (researchers + companies) | 1K-100K |
| `refresh_tokens` | JWT refresh tokens | 5K-500K |
| `programs` | Bug bounty programs | 100-10K |
| `assets` | Program scope (domains, APIs) | 500-50K |
| `reward_tiers` | Bounty amounts by severity | 500-50K |
| `reports` | Vulnerability submissions | 10K-1M |
| `comments` | Triage communication | 50K-5M |
| `attachments` | Proof-of-concept files | 10K-1M |

---

## Entity Relationship Diagram

```
┌──────────────────────────────┐
│          users               │
│──────────────────────────────│
│ id (UUID v7) PK              │
│ email (unique, indexed)      │
│ hashed_password              │
│ full_name                    │
│ role (enum)                  │
│ is_active                    │
│ is_verified                  │
│ token_version                │
│ company_name                 │
│ bio                          │
│ website                      │
│ reputation_score             │
│ created_at, updated_at       │
└──────────────┬───────────────┘
               │
    ┌──────────┼──────────┬──────────────┐
    │          │          │              │
    │ 1        │ 1        │ 1            │
    │          │          │              │
    ▼ *        ▼ *        ▼ *            ▼ *
┌─────────────┐ ┌──────────┐ ┌────────────┐ ┌────────────────┐
│refresh_     │ │programs  │ │  reports   │ │                │
│tokens       │ │          │ │            │ │                │
│─────────────│ │──────────│ │────────────│ │                │
│id PK        │ │id PK     │ │id PK       │ │                │
│user_id FK   │ │company_id│ │program_id  │ │                │
│token_hash   │ │name      │ │researcher  │ │                │
│device_info  │ │slug (idx)│ │  _id FK    │ │                │
│family_id    │ │description│ │title      │ │                │
│ip_address   │ │rules     │ │description │ │                │
│expires_at   │ │response  │ │steps_to    │ │                │
│created_at   │ │  _sla_hrs│ │  _reproduce│ │                │
└─────────────┘ │status    │ │impact      │ │                │
                │  (indexed)│ │severity    │ │                │
                │visibility│ │  _submitted│ │                │
                │created_at│ │severity    │ │                │
                │updated_at│ │  _final    │ │                │
                └────┬─────┘ │status (idx)│ │                │
                     │       │cvss_score  │ │                │
           ┌─────────┼────┐  │cwe_id      │ │                │
           │         │    │  │bounty_amt  │ │                │
           │ 1       │ 1  │  │duplicate   │ │                │
           │         │    │  │  _of_id    │ │                │
           ▼ *       ▼ *  │  │triaged_at  │ │                │
        ┌─────┐  ┌─────┐ │  │resolved_at │ │                │
        │asset│  │reward│ │  │disclosed_at│ │                │
        │     │  │tier │ │  │created_at  │ │                │
        │─────│  │─────│ │  │updated_at  │ │                │
        │id PK│  │id PK│ │  └──────┬─────┘ │                │
        │prog │  │prog │ │         │       │                │
        │ _id │  │ _id │ │    ┌────┼────┐  │                │
        │type │  │seve │ │    │ 1       │ 1│                │
        │targ │  │ rity│ │    │         │  │                │
        │ et  │  │amnt │ │    ▼ *       ▼ *│                │
        │crea │  │crea │ │  ┌────────┐ ┌──┴────┐            │
        │ted  │  │ted  │ │  │comments│ │attach │            │
        │     │  │     │ │  │        │ │ments  │            │
        └─────┘  └─────┘ │  │────────│ │───────│            │
                         │  │id PK   │ │id PK  │            │
                         │  │report  │ │report │            │
                         │  │  _id FK│ │  _id  │            │
                         │  │author  │ │  FK   │            │
                         │  │  _id FK│ │file   │            │
                         │  │content │ │  _name│            │
                         │  │created │ │file   │            │
                         │  │  _at   │ │  _size│            │
                         │  │updated │ │file   │            │
                         │  │  _at   │ │  _type│            │
                         │  └────────┘ │s3_key │            │
                         │             │created│            │
                         │             │  _at  │            │
                         │             └───────┘            │
                         │                                  │
                         └──────────────────────────────────┘
```

---

## Table Schemas

### users

**Purpose:** Store user accounts (researchers, companies, admins)

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    role VARCHAR(50) DEFAULT 'user',  -- SafeEnum: stores value, not name
    token_version INTEGER DEFAULT 0,
    company_name VARCHAR(255),
    bio TEXT,
    website VARCHAR(255),
    reputation_score INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_users_email ON users(email);
```

**Key Fields:**

- `id` - UUID v7 (time-sortable, globally unique)
- `email` - Unique identifier (indexed for fast lookups)
- `hashed_password` - Argon2id hash (never store plaintext)
- `role` - SafeEnum pattern (stores "user", not "USER")
- `token_version` - Increment to invalidate all tokens
- `reputation_score` - Researcher reputation (bounties earned, reports accepted)

**Design Decisions:**

1. **Single user table** - Both researchers and companies use the same table
   - Alternative: Separate `researchers` and `companies` tables
   - Reason: Same authentication, reduces JOIN complexity
   - Trade-off: Some fields unused (researchers don't have `company_name`)

2. **Soft deletes NOT used** - When a user is deleted, they're gone
   - Alternative: Add `deleted_at` column
   - Reason: GDPR compliance requires true deletion
   - Exception: Admin can set `is_active = false` to suspend accounts

3. **Token versioning** - Increment to invalidate all tokens instantly
   - Alternative: Maintain token blacklist
   - Reason: Simpler, no need to clean up old blacklist entries

### programs

**Purpose:** Bug bounty programs hosted by companies

```sql
CREATE TABLE programs (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    company_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    rules TEXT,
    response_sla_hours INTEGER DEFAULT 72,
    status VARCHAR(50) DEFAULT 'draft',  -- draft, active, paused, closed
    visibility VARCHAR(50) DEFAULT 'public',  -- public, private, invite_only
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_programs_slug ON programs(slug);
CREATE INDEX idx_programs_status ON programs(status);
CREATE INDEX idx_programs_company_id ON programs(company_id);
```

**Key Fields:**

- `slug` - URL-friendly identifier (`/programs/acme-corp`)
- `status` - Program lifecycle (indexed for filtering active programs)
- `visibility` - Who can see the program
- `response_sla_hours` - How quickly company must respond (72h default)

**Design Decisions:**

1. **Slug for URLs** - Use slug instead of ID in URLs
   - Alternative: Use UUID in URL (`/programs/018d3f54-8c3a-7000`)
   - Reason: Better UX, SEO-friendly
   - Constraint: Must be unique and immutable

2. **Status enum** - Draft → Active → Paused/Closed
   - Draft: Not visible, company is setting up
   - Active: Accepting submissions
   - Paused: Temporarily closed (no new submissions)
   - Closed: Permanently closed

3. **SLA tracking** - `response_sla_hours` sets expectation
   - Used to calculate if company is meeting SLA
   - Can be used for automated notifications

### reports

**Purpose:** Vulnerability reports submitted by researchers

```sql
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    researcher_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    steps_to_reproduce TEXT,
    impact TEXT,
    severity_submitted VARCHAR(50) DEFAULT 'medium',
    severity_final VARCHAR(50),
    status VARCHAR(50) DEFAULT 'new',  -- new, triaging, accepted, etc.
    cvss_score NUMERIC(3, 1),  -- 0.0 to 10.0
    cwe_id VARCHAR(20),  -- CWE-79, CWE-89, etc.
    bounty_amount INTEGER,
    duplicate_of_id UUID REFERENCES reports(id) ON DELETE SET NULL,
    triaged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    disclosed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_reports_program_id ON reports(program_id);
CREATE INDEX idx_reports_researcher_id ON reports(researcher_id);
CREATE INDEX idx_reports_status ON reports(status);
```

**Key Fields:**

- `severity_submitted` - Researcher's assessment
- `severity_final` - Company's final assessment (may differ)
- `status` - Report lifecycle (indexed for filtering)
- `cvss_score` - Common Vulnerability Scoring System (0.0-10.0)
- `cwe_id` - Common Weakness Enumeration (CWE-79 = XSS)
- `duplicate_of_id` - Self-referencing FK for duplicate tracking
- `triaged_at`, `resolved_at`, `disclosed_at` - Lifecycle timestamps

**Design Decisions:**

1. **Two severity fields** - Submitted vs final
   - Reason: Researcher may overestimate severity
   - Company can adjust during triage
   - Transparency: Both values are visible

2. **Status workflow** - Linear progression with branches
   ```
   NEW → TRIAGING → NEEDS_MORE_INFO → TRIAGING
         ↓
         ACCEPTED → RESOLVED → DISCLOSED
         ↓
         DUPLICATE
         ↓
         NOT_APPLICABLE
         ↓
         INFORMATIVE
   ```

3. **Duplicate tracking** - `duplicate_of_id` links to original
   - Alternative: Store duplicate IDs in array
   - Reason: Simplicity, can traverse duplicate chain
   - Caveat: Must prevent circular references

4. **CVSS + CWE** - Industry-standard vulnerability classification
   - CVSS score: Numeric severity (6.0-6.9 = medium)
   - CWE ID: Weakness category (CWE-79 = XSS)
   - Both are optional but recommended

### refresh_tokens

**Purpose:** Store JWT refresh tokens for authentication

```sql
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,  -- SHA-256 hash
    device_info VARCHAR(255),
    ip_address VARCHAR(45),  -- IPv6-compatible
    family_id UUID NOT NULL,  -- For token rotation detection
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

**Key Fields:**

- `token_hash` - SHA-256 hash of refresh token (not plaintext!)
- `family_id` - Tracks token rotation chain
- `device_info` - User agent string
- `ip_address` - For security monitoring
- `expires_at` - Tokens expire after 7 days

**Design Decisions:**

1. **Hash tokens** - Store SHA-256 hash, not plaintext
   - If database is compromised, attacker can't use tokens
   - Must hash token before querying database

2. **Token rotation** - Each refresh creates new token
   - Old token is deleted
   - New token has same `family_id`
   - If old token is reused → detected by `family_id` mismatch

3. **Multi-device support** - User can have multiple refresh tokens
   - Each device/session gets its own token
   - Logout deletes specific token
   - Logout-all deletes all tokens for user

### assets

**Purpose:** Define program scope (domains, APIs, mobile apps)

```sql
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,  -- web, api, mobile, other
    target VARCHAR(255) NOT NULL,  -- *.example.com, api.example.com
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_assets_program_id ON assets(program_id);
```

**Key Fields:**

- `type` - Asset category (web app, API, mobile app, etc.)
- `target` - The actual asset (domain, API endpoint, app package name)

**Design Decisions:**

1. **Separate table** - Not embedded in `programs`
   - Reason: Programs can have many assets
   - Easier to add/remove scope items
   - Can query "which programs include example.com?"

### reward_tiers

**Purpose:** Define bounty amounts by severity

```sql
CREATE TABLE reward_tiers (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    severity VARCHAR(50) NOT NULL,  -- critical, high, medium, low
    amount INTEGER NOT NULL,  -- in USD cents
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_reward_tiers_program_id ON reward_tiers(program_id);
```

**Key Fields:**

- `severity` - Critical, high, medium, low, informational
- `amount` - Bounty in USD cents (e.g., 50000 = $500.00)

**Design Decisions:**

1. **Store cents, not dollars** - Avoid floating point issues
   - `amount = 50000` (integer)
   - Display as `$500.00` in UI
   - Prevents rounding errors

2. **Per-program tiers** - Each program sets its own bounties
   - Alternative: Platform-wide default tiers
   - Reason: Flexibility, companies have different budgets

### comments

**Purpose:** Communication between researcher and company

```sql
CREATE TABLE comments (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    author_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    is_internal BOOLEAN DEFAULT FALSE,  -- Internal company notes
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_comments_report_id ON comments(report_id);
CREATE INDEX idx_comments_author_id ON comments(author_id);
```

**Key Fields:**

- `is_internal` - Company-only notes (not visible to researcher)
- `content` - Markdown-formatted text

**Design Decisions:**

1. **Separate table** - Not embedded in `reports`
   - Reason: Reports can have many comments
   - Chronological order preserved
   - Can notify on new comments

2. **Internal comments** - `is_internal = true`
   - Company can discuss report privately
   - Researcher never sees these
   - Useful for triage notes

### attachments

**Purpose:** Proof-of-concept files (screenshots, videos, scripts)

```sql
CREATE TABLE attachments (
    id UUID PRIMARY KEY DEFAULT uuid_v7(),
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,  -- in bytes
    file_type VARCHAR(100) NOT NULL,  -- image/png, video/mp4, etc.
    s3_key VARCHAR(255) NOT NULL,  -- S3 object key
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_attachments_report_id ON attachments(report_id);
```

**Key Fields:**

- `file_name` - Original filename
- `file_size` - In bytes
- `file_type` - MIME type
- `s3_key` - S3 storage key (actual file not in database)

**Design Decisions:**

1. **Metadata only** - Files stored in S3, not database
   - Reason: Database is for structured data, not binary blobs
   - Better performance
   - Cheaper storage

2. **No soft deletes** - When report is deleted, attachments are deleted
   - S3 objects are also deleted (via lifecycle policy or webhook)

---

## Design Decisions

### UUID v7 vs Auto-Increment

**Auto-Increment IDs:**
```sql
id SERIAL PRIMARY KEY  -- 1, 2, 3, 4, ...
```

Problems:
- Predictable (enumerate all records by guessing IDs)
- Not globally unique (can't merge databases)
- Require database round-trip to generate

**UUID v4 (Random):**
```sql
id UUID PRIMARY KEY DEFAULT gen_random_uuid()
```

Problems:
- Random = bad for database indexes
- Not time-sortable (`ORDER BY id` is meaningless)

**UUID v7 (Best of both):**
```sql
id UUID PRIMARY KEY DEFAULT uuid_v7()
```

Benefits:
- Time-sortable (first 48 bits = Unix timestamp in ms)
- Globally unique (no collisions)
- Good for indexes (lexicographic order = chronological order)
- Secure (remaining bits are random)

```
018d3f54-8c3a-7000-a234-56789abcdef0
^^^^^^^^^^^^^^^^ ← timestamp (2024-01-15 12:34:56.789)
                ^^^^^^^^^^^^^^^^^^^^ ← random
```

### SafeEnum Pattern

**Problem:** SQLAlchemy's default enum stores the Python name:

```python
class Status(enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"

# Database stores: "ACTIVE" (the Python name)
```

If you rename the enum:

```python
class Status(enum.Enum):
    RUNNING = "active"  # Renamed
    PAUSED = "paused"

# Database has "ACTIVE", Python doesn't recognize it → breaks!
```

**Solution: SafeEnum stores the value:**

```python
class Status(SafeEnum):
    ACTIVE = "active"
    PAUSED = "paused"

# Database stores: "active" (the value)
```

Now you can safely rename:

```python
class Status(SafeEnum):
    RUNNING = "active"  # Value is still "active"
    PAUSED = "paused"

# Database has "active", maps to Status.RUNNING ✓
```

### Cascade Deletes

When a parent record is deleted, what happens to children?

**Options:**

1. `ON DELETE CASCADE` - Delete children
2. `ON DELETE SET NULL` - Set foreign key to NULL
3. `ON DELETE RESTRICT` - Prevent deletion if children exist

**Our choices:**

```sql
-- User deleted → delete all their refresh tokens
user_id UUID REFERENCES users(id) ON DELETE CASCADE

-- User deleted → delete all their reports
researcher_id UUID REFERENCES users(id) ON DELETE CASCADE

-- Program deleted → delete all reports
program_id UUID REFERENCES programs(id) ON DELETE CASCADE

-- Report deleted → set duplicate_of_id to NULL
duplicate_of_id UUID REFERENCES reports(id) ON DELETE SET NULL
```

**Why CASCADE for reports?**
- When a program is deleted, its reports become orphaned
- No point keeping reports for deleted programs
- Alternative: Soft delete programs (`deleted_at`)

**Why SET NULL for duplicates?**
- If original report is deleted, duplicates can stand alone
- Don't cascade delete (duplicate might be wrong)

### Lazy Loading Disabled

SQLAlchemy's default behavior:

```python
user = await session.get(User, user_id)
programs = user.programs  # ← Implicit query! (N+1 problem)
```

**Problem:** Each access triggers a database query

**Solution:** Set `lazy="raise"`

```python
class User(Base):
    programs: Mapped[list[Program]] = relationship(
        back_populates="company",
        lazy="raise",  # ← Raise error on lazy load
    )

# Now you must explicitly load:
stmt = select(User).options(selectinload(User.programs))
user = await session.execute(stmt)
```

Forces developers to think about query efficiency.

---

## Indexes and Performance

### When to Index

**Index columns that are:**
1. Used in WHERE clauses (`WHERE email = ?`)
2. Used in JOIN conditions (`ON users.id = reports.researcher_id`)
3. Used for uniqueness (`UNIQUE INDEX`)
4. Used for sorting (`ORDER BY created_at`)

**Don't index:**
- Columns with low cardinality (`is_active` - only 2 values)
- Columns rarely queried
- Small tables (< 1000 rows)

### Our Indexes

```sql
-- Unique indexes (also enforce uniqueness)
CREATE UNIQUE INDEX idx_users_email ON users(email);
CREATE UNIQUE INDEX idx_programs_slug ON programs(slug);

-- Foreign key indexes (for JOINs)
CREATE INDEX idx_reports_program_id ON reports(program_id);
CREATE INDEX idx_reports_researcher_id ON reports(researcher_id);
CREATE INDEX idx_comments_report_id ON comments(report_id);

-- Filter indexes (for WHERE clauses)
CREATE INDEX idx_programs_status ON programs(status);
CREATE INDEX idx_reports_status ON reports(status);
```

### Query Performance

**Slow query:**
```python
# Gets all reports, then filters in Python
reports = await session.execute(select(Report))
active_reports = [r for r in reports if r.status == "new"]
```

**Fast query:**
```python
# Filters in database (uses index)
stmt = select(Report).where(Report.status == ReportStatus.NEW)
reports = await session.execute(stmt)
```

**EXPLAIN ANALYZE:**

```sql
EXPLAIN ANALYZE
SELECT * FROM reports WHERE status = 'new';

-- Good: Index Scan using idx_reports_status
-- Bad: Seq Scan on reports
```

---

## Migrations

### Why Alembic?

- Version control for database schema
- Automatic migration generation
- Rollback support
- Team collaboration (everyone has same schema)

### Creating Migrations

```bash
# 1. Modify a model
class User(Base):
    bio: Mapped[str | None] = mapped_column(Text, default=None)  # Added

# 2. Generate migration
just migration "Add user bio field"

# 3. Review generated migration
# alembic/versions/20240115_add_user_bio.py
def upgrade():
    op.add_column('users', sa.Column('bio', sa.Text(), nullable=True))

def downgrade():
    op.drop_column('users', 'bio')

# 4. Apply migration
just migrate head
```

### Migration Best Practices

1. **Always review generated migrations** - Alembic may not detect everything
2. **Test rollback** - Ensure `downgrade()` works
3. **Add indexes in separate migrations** - Can take time on large tables
4. **Use migrations for data changes** - Not just schema

**Example data migration:**

```python
def upgrade():
    # Add column
    op.add_column('users', sa.Column('reputation_score', sa.Integer(), default=0))

    # Backfill existing users
    op.execute("UPDATE users SET reputation_score = 0 WHERE reputation_score IS NULL")

    # Make NOT NULL
    op.alter_column('users', 'reputation_score', nullable=False)
```

---

## Common Queries

### Get Active Programs

```python
stmt = (
    select(Program)
    .where(Program.status == ProgramStatus.ACTIVE)
    .order_by(Program.created_at.desc())
)
programs = await session.execute(stmt)
```

### Get User's Reports

```python
stmt = (
    select(Report)
    .where(Report.researcher_id == user_id)
    .order_by(Report.created_at.desc())
)
reports = await session.execute(stmt)
```

### Get Report with Comments (Eager Loading)

```python
from sqlalchemy.orm import selectinload

stmt = (
    select(Report)
    .where(Report.id == report_id)
    .options(
        selectinload(Report.comments),
        selectinload(Report.attachments),
    )
)
report = await session.execute(stmt)
```

### Count Reports by Status

```python
from sqlalchemy import func

stmt = (
    select(Report.status, func.count(Report.id))
    .where(Report.program_id == program_id)
    .group_by(Report.status)
)
results = await session.execute(stmt)
```

### Find Duplicate Reports

```python
stmt = (
    select(Report)
    .where(Report.duplicate_of_id == original_report_id)
)
duplicates = await session.execute(stmt)
```

---

## Conclusion

Key takeaways:

1. **UUID v7** - Time-sortable, globally unique IDs
2. **SafeEnum** - Store enum values, not names
3. **Indexes** - Index foreign keys, unique columns, filter columns
4. **Migrations** - Version control for database schema
5. **Relationships** - Use `lazy="raise"` to prevent N+1 queries
6. **Cascade Deletes** - Think about what happens when parent is deleted

For more information:
- System architecture: [ARCHITECTURE.md](./ARCHITECTURE.md)
- Design patterns: [PATTERNS.md](./PATTERNS.md)
- Security features: [SECURITY.md](./SECURITY.md)
- Hands-on tutorial: [GETTING-STARTED.md](./GETTING-STARTED.md)
