# Production Pydantic v2 Guide for FastAPI (2025)

Pydantic v2 represents a complete architectural overhaul from v1, with a Rust-powered core (`pydantic-core`) that delivers 5-17x performance improvements. The API has been redesigned around `Annotated` types, new validator patterns, and explicit serialization modes. This guide focuses on 2025 best practices—not tutorial basics—with emphasis on patterns that scale in production FastAPI applications.

---

## Core v2 Changes That Actually Matter

### The Rust Core Changes Everything

Pydantic v2's validation engine is written in Rust and exposed via PyO3. This isn't just "faster validation"—it fundamentally changes how you should think about data processing:

```python
# v1 pattern (deprecated)
from pydantic import BaseModel, validator

class User(BaseModel):
    age: int
    
    @validator('age')
    def check_age(cls, v):
        if v < 18:
            raise ValueError('too young')
        return v

# v2 pattern (correct)
from pydantic import BaseModel, field_validator

class User(BaseModel):
    age: int
    
    @field_validator('age')
    @classmethod
    def check_age(cls, v: int) -> int:
        if v < 18:
            raise ValueError('too young')
        return v
```

**Key differences:**
- `@field_validator` replaces `@validator`—the signature is now type-safe
- Validators are explicitly `@classmethod` decorated
- No more `each_item` keyword; use `Annotated` for collection items

### Method Name Changes You Must Know

| v1 Method | v2 Replacement | Purpose |
|-----------|----------------|---------|
| `.dict()` | `.model_dump()` | Serialize to dict |
| `.json()` | `.model_dump_json()` | Serialize to JSON string |
| `parse_obj()` | `.model_validate()` | Validate dict/object |
| `parse_raw()` | `.model_validate_json()` | Validate JSON string |
| `from_orm()` | `.model_validate()` + `from_attributes=True` | Load from ORM models |

**Critical:** The old v1 methods still exist but are deprecated. Using them in new code is a mistake.

---

## Annotated: The New Foundation

`Annotated` is now the primary way to attach metadata to fields. This creates reusable, composable type aliases:

```python
from typing import Annotated
from pydantic import BaseModel, Field, AfterValidator

# Reusable validated types
PositiveInt = Annotated[int, Field(gt=0)]
NonEmptyStr = Annotated[str, Field(min_length=1)]
EmailStr = Annotated[str, Field(pattern=r'^[\w\.-]+@[\w\.-]+\.\w+$')]

# Composable validation
def check_even(v: int) -> int:
    if v % 2 != 0:
        raise ValueError('must be even')
    return v

EvenPositiveInt = Annotated[int, Field(gt=0), AfterValidator(check_even)]

class Product(BaseModel):
    quantity: PositiveInt
    sku: NonEmptyStr
    batch_size: EvenPositiveInt
```

**Why this matters:** Type aliases centralize validation logic. Change `PositiveInt` once, and every field using it updates automatically.

### Field Metadata vs Validation

```python
from pydantic import Field

class Article(BaseModel):
    # Metadata: describes the field, doesn't validate
    title: str = Field(
        description="Article title",
        examples=["How to Scale FastAPI"],
        json_schema_extra={"maxLength": 200}
    )
    
    # Constraints: actually validate
    word_count: int = Field(gt=0, le=10000)
    tags: list[str] = Field(min_length=1, max_length=10)
```

**Metadata** appears in OpenAPI/JSON schema but doesn't enforce anything. **Constraints** raise `ValidationError` on violation.

---

## Validators: The Four Modes

Pydantic v2 has four validator types with explicit execution order:

### 1. Before Validators

Run **before** Pydantic's type coercion. Handle raw input:

```python
from pydantic import BaseModel, field_validator

class Event(BaseModel):
    timestamp: datetime
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def parse_timestamp(cls, v):
        # v could be str, int, datetime, anything
        if isinstance(v, str):
            return datetime.fromisoformat(v)
        if isinstance(v, int):
            return datetime.fromtimestamp(v)
        return v  # Let Pydantic handle it
```

**Use when:** You need to preprocess raw data before type checking.

### 2. After Validators (default)

Run **after** Pydantic validates the type. Input is guaranteed to match the type annotation:

```python
from pydantic import field_validator

class User(BaseModel):
    username: str
    
    @field_validator('username')  # mode='after' is default
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.lower().strip()
```

**Use when:** You need to transform already-validated data.

### 3. Wrap Validators

Run **around** Pydantic's validation—you control whether to call the handler:

```python
from pydantic import WrapValidator, ValidationError
from typing import Annotated

def truncate_or_fail(v, handler):
    try:
        return handler(v)  # Try normal validation
    except ValidationError as e:
        if e.errors()[0]['type'] == 'string_too_long':
            return v[:100]  # Truncate instead of failing
        raise

LenientStr = Annotated[str, Field(max_length=100), WrapValidator(truncate_or_fail)]

class Post(BaseModel):
    title: LenientStr
```

**Use when:** You need to catch validation errors and recover.

### 4. Plain Validators

Replace Pydantic's validation entirely. **Dangerous** but sometimes necessary:

```python
from pydantic import PlainValidator
from typing import Annotated

def custom_validation(v):
    # No type checking happens—you're responsible for everything
    return int(v) * 2

WeirdInt = Annotated[int, PlainValidator(custom_validation)]

class Model(BaseModel):
    number: WeirdInt

print(Model(number='5').number)  # 10
print(Model(number='invalid').number)  # 'invalidinvalid' (no error!)
```

**Use when:** Pydantic's type system can't express your validation logic.

### Annotated Validators vs Decorator Syntax

Both styles work; choose based on reusability:

```python
# Annotated: reusable across models
AgeInt = Annotated[int, AfterValidator(lambda v: v if v >= 18 else 18)]

class User(BaseModel):
    age: AgeInt

# Decorator: model-specific logic
class User(BaseModel):
    age: int
    
    @field_validator('age')
    @classmethod
    def min_age(cls, v: int) -> int:
        return v if v >= 18 else 18
```

### Accessing Other Fields in Validators

Use `ValidationInfo` to access previously validated fields:

```python
from pydantic import field_validator, ValidationInfo

class PasswordReset(BaseModel):
    password: str
    password_confirm: str
    
    @field_validator('password_confirm')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo) -> str:
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('passwords do not match')
        return v
```

**Critical:** Field order matters. `password` must be defined before `password_confirm`.

---

## Model Serialization: Python vs JSON Mode

Pydantic v2 has two serialization modes with different outputs:

```python
from datetime import datetime
from pydantic import BaseModel

class Event(BaseModel):
    name: str
    occurred_at: datetime
    tags: set[str]

event = Event(name='Launch', occurred_at='2025-01-01', tags={'python', 'api'})

# Python mode: preserves Python types
print(event.model_dump())
# {'name': 'Launch', 
#  'occurred_at': datetime.datetime(2025, 1, 1, 0, 0), 
#  'tags': {'python', 'api'}}

# JSON mode: only JSON-compatible types
print(event.model_dump(mode='json'))
# {'name': 'Launch', 
#  'occurred_at': '2025-01-01T00:00:00', 
#  'tags': ['api', 'python']}
```

**Use JSON mode when:**
- Sending data to FastAPI response models
- Storing in Redis/DynamoDB (requires JSON)
- Passing to `json.dumps()` yourself

**Use Python mode when:**
- Manipulating data in Python
- Passing to other Python functions
- Need access to Python objects (datetime, UUID, etc.)

### The serialize_as_any Gotcha

In v2, nested subclass fields are serialized according to the annotated type, **not the runtime type**:

```python
class User(BaseModel):
    name: str

class AdminUser(User):
    permissions: list[str]

class Company(BaseModel):
    employees: list[User]

admin = AdminUser(name='Alice', permissions=['admin'])
company = Company(employees=[admin])

# v2 default: only User fields serialized
print(company.model_dump())
# {'employees': [{'name': 'Alice'}]}  # permissions missing!

# To get v1 behavior, use serialize_as_any
print(company.model_dump(serialize_as_any=True))
# {'employees': [{'name': 'Alice', 'permissions': ['admin']}]}
```

**Fix:** Annotate with `SerializeAsAny` if you need duck-typing:

```python
from pydantic import SerializeAsAny

class Company(BaseModel):
    employees: list[SerializeAsAny[User]]  # Now includes subclass fields
```

---

## Computed Fields: Properties That Serialize

Computed fields are properties that automatically appear in `model_dump()`:

```python
from pydantic import BaseModel, computed_field

class Rectangle(BaseModel):
    width: float
    height: float
    
    @computed_field
    @property
    def area(self) -> float:
        return self.width * self.height

rect = Rectangle(width=10, height=5)
print(rect.area)  # 50.0
print(rect.model_dump())  # {'width': 10.0, 'height': 5.0, 'area': 50.0}
```

**Critical differences from regular properties:**
- Included in `model_dump()` and `model_dump_json()`
- Appear in JSON schema (marked `readOnly`)
- Cannot be set during initialization
- Only support `alias`, not `validation_alias`/`serialization_alias`

### Computed Fields with Setters

```python
from pydantic import computed_field

class Square(BaseModel):
    width: float
    
    @computed_field
    @property
    def area(self) -> float:
        return self.width ** 2
    
    @area.setter
    def area(self, value: float):
        self.width = value ** 0.5

square = Square(width=4)
square.area = 25  # Sets width to 5.0
print(square.model_dump())  # {'width': 5.0, 'area': 25.0}
```

**Use case:** Exposing derived data in APIs without storing it.

---

## ConfigDict: Model-Level Configuration

`ConfigDict` replaces the v1 `Config` class:

```python
from pydantic import BaseModel, ConfigDict, Field

class StrictModel(BaseModel):
    model_config = ConfigDict(
        strict=True,  # No type coercion
        frozen=True,  # Immutable (replaces allow_mutation=False)
        validate_assignment=True,  # Validate on attribute assignment
        extra='forbid',  # Reject extra fields
        from_attributes=True,  # Enable ORM mode
        str_strip_whitespace=True,  # Strip strings automatically
        use_attribute_docstrings=True,  # Use docstrings as descriptions
    )
    
    age: int
    """User's age in years"""
```

### Strict Mode Explained

By default, Pydantic coerces types (lax mode):

```python
class User(BaseModel):
    age: int

print(User(age='25').age)  # 25 (int, coerced from str)
```

Strict mode disables coercion:

```python
class User(BaseModel):
    model_config = ConfigDict(strict=True)
    age: int

User(age='25')  # ValidationError: Input should be a valid integer
```

**Per-field override:**

```python
class User(BaseModel):
    model_config = ConfigDict(strict=True)
    age: int
    name: str = Field(strict=False)  # Only this field allows coercion
```

### from_attributes: The New ORM Mode

Replaces v1's `orm_mode=True`:

```python
from pydantic import ConfigDict
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

class User(DeclarativeBase):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str]

class UserSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str

# Load from SQLAlchemy model
db_user = session.get(User, 1)
user_data = UserSchema.model_validate(db_user)
```

**Critical:** Without `from_attributes=True`, you can only validate dicts.

---

## TypeAdapter: Validation for Non-Model Types

`TypeAdapter` validates any type, not just `BaseModel`:

```python
from pydantic import TypeAdapter, ValidationError
from typing import TypedDict

class UserDict(TypedDict):
    name: str
    age: int

UserListAdapter = TypeAdapter(list[UserDict])

# Validate and coerce
data = [{'name': 'Alice', 'age': '30'}]
users = UserListAdapter.validate_python(data)
print(users)  # [{'name': 'Alice', 'age': 30}]

# Serialize
json_bytes = UserListAdapter.dump_json(users)
```

**Use cases:**
- Validating API responses (don't want full `BaseModel`)
- Working with `TypedDict` or dataclasses
- Generic container types (`list[int]`, `dict[str, float]`)

### TypeAdapter for Constrained Types

```python
from pydantic import Field
from typing import Annotated

PositiveInt = Annotated[int, Field(gt=0)]
adapter = TypeAdapter(PositiveInt)

adapter.validate_python(5)  # OK
adapter.validate_python(-5)  # ValidationError
```

---

## Discriminated Unions: Type-Safe Polymorphism

Discriminated unions are FastAPI's secret weapon for handling polymorphic request/response data:

```python
from typing import Literal, Union
from pydantic import BaseModel, Field

class Cat(BaseModel):
    type: Literal['cat']
    meows: int

class Dog(BaseModel):
    type: Literal['dog']
    barks: int

class Pet(BaseModel):
    pet: Union[Cat, Dog] = Field(discriminator='type')

# Efficient validation—checks 'type' field first
pet = Pet.model_validate({'pet': {'type': 'cat', 'meows': 5}})
print(type(pet.pet))  # <class '__main__.Cat'>
```

### How Discriminators Improve Performance

Without discriminator, Pydantic tries each union member sequentially:

```python
# Slow: tries Cat, fails, tries Dog
pet: Union[Cat, Dog]
```

With discriminator, Pydantic jumps directly to the correct type:

```python
# Fast: reads 'type' field, validates only Dog
pet: Union[Cat, Dog] = Field(discriminator='type')
```

**Production win:** On unions with 5+ members, discriminators are 10x+ faster.

### Nested Discriminated Unions

```python
class BlackCat(BaseModel):
    species: Literal['cat']
    color: Literal['black']
    black_name: str

class WhiteCat(BaseModel):
    species: Literal['cat']
    color: Literal['white']
    white_name: str

Cat = Annotated[Union[BlackCat, WhiteCat], Field(discriminator='color')]

class Dog(BaseModel):
    species: Literal['dog']
    name: str

Pet = Annotated[Union[Cat, Dog], Field(discriminator='species')]
```

### Fallback Pattern for Unknown Types

Perfect for webhook handlers that must not crash:

```python
from typing import Annotated

class GenericEvent(BaseModel):
    type: str
    data: dict

class UserCreated(BaseModel):
    type: Literal['user.created']
    user_id: int

KnownEvents = Annotated[Union[UserCreated], Field(discriminator='type')]

# Outer union tries discriminated first, falls back to generic
Event = Annotated[
    Union[KnownEvents, GenericEvent],
    Field(union_mode='left_to_right')
]

# Unknown type → GenericEvent (doesn't crash)
Event.model_validate({'type': 'unknown', 'data': {}})
```

**Use case:** Third-party APIs that add new event types without notice.

---

## Alias Patterns: validation_alias vs serialization_alias

Separate aliases for input and output:

```python
from pydantic import BaseModel, Field

class User(BaseModel):
    # Accept both snake_case and camelCase on input
    first_name: str = Field(validation_alias='firstName')
    
    # Always output as camelCase
    last_name: str = Field(
        validation_alias='lastName',
        serialization_alias='lastName'
    )

# Validate with camelCase
user = User(firstName='John', lastName='Doe')

# Serialize with snake_case (default) or camelCase
print(user.model_dump())  # {'first_name': 'John', 'last_name': 'Doe'}
print(user.model_dump(by_alias=True))  # {'first_name': 'John', 'lastName': 'Doe'}
```

### AliasPath: Extract Nested Fields

```python
from pydantic import AliasPath

class User(BaseModel):
    first_name: str = Field(validation_alias=AliasPath('name', 'first'))
    last_name: str = Field(validation_alias=AliasPath('name', 'last'))
    city: str = Field(validation_alias=AliasPath('address', 'city'))

# Validate nested structure
user = User.model_validate({
    'name': {'first': 'Jane', 'last': 'Doe'},
    'address': {'city': 'NYC', 'zip': '10001'}
})
print(user.model_dump())  
# {'first_name': 'Jane', 'last_name': 'Doe', 'city': 'NYC'}
```

**Use case:** Flattening deeply nested API responses.

### AliasChoices: Multiple Valid Aliases

```python
from pydantic import AliasChoices

class User(BaseModel):
    username: str = Field(
        validation_alias=AliasChoices('username', 'user', 'login')
    )

# All of these work
User(username='alice')
User(user='alice')
User(login='alice')
```

**Use case:** Supporting legacy API versions during migration.

### Global Alias Generators

```python
from pydantic import ConfigDict, AliasGenerator

def to_camel(field: str) -> str:
    components = field.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])

class User(BaseModel):
    model_config = ConfigDict(
        alias_generator=AliasGenerator(
            validation_alias=str.lower,  # Accept any case
            serialization_alias=to_camel  # Output camelCase
        )
    )
    
    first_name: str
    last_name: str

user = User(FIRST_NAME='John', last_name='Doe')
print(user.model_dump(by_alias=True))  # {'firstName': 'John', 'lastName': 'Doe'}
```

---

## FastAPI Integration Patterns

### Request/Response Schema Separation

**Anti-pattern:** Using the same model for input and output:

```python
# DON'T DO THIS
class User(BaseModel):
    id: int  # Who sets this on creation?
    email: str
    password: str  # Leaked in responses!
```

**Correct pattern:**

```python
class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=8)

class UserUpdate(BaseModel):
    email: str | None = None
    password: str | None = Field(None, min_length=8)

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    created_at: datetime

@router.post('/users', response_model=UserResponse)
async def create_user(data: UserCreate):
    user = User(email=data.email, password=hash_password(data.password))
    session.add(user)
    await session.commit()
    return user  # FastAPI uses response_model to serialize
```

### The response_model Double Validation Trap

FastAPI validates your return value twice:

```python
@router.get('/', response_model=UserResponse)
def get_user():
    user = UserResponse(id=1, email='test@example.com')  # Validation #1
    return user  # Validation #2 (FastAPI converts to dict, validates again)
```

**This is intentional:** FastAPI guarantees `response_model` matches output, even if you return the wrong type.

**Performance note:** If you return the exact `response_model` type, the cost is minimal. If you return a dict/ORM object, full validation runs.

### Depend on Pydantic for FastAPI Dependencies

```python
from pydantic import BaseModel, Field
from typing import Annotated
from fastapi import Depends, Query

class Pagination(BaseModel):
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)

def get_pagination(
    page: Annotated[int, Query(ge=1)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 20
) -> Pagination:
    return Pagination(page=page, size=size)

@router.get('/items')
def list_items(pagination: Annotated[Pagination, Depends(get_pagination)]):
    # pagination is validated
    return {'page': pagination.page, 'size': pagination.size}
```

---

## Anti-Patterns to Avoid

### Don't Use mutable Defaults

```python
# WRONG
class Team(BaseModel):
    members: list[str] = []  # Shared between instances!

# CORRECT
class Team(BaseModel):
    members: list[str] = Field(default_factory=list)
```

### Don't Validate in __init__

```python
# WRONG
class User(BaseModel):
    email: str
    
    def __init__(self, **data):
        super().__init__(**data)
        # Custom logic here breaks validation context
        self.email = self.email.lower()

# CORRECT
class User(BaseModel):
    email: str
    
    @field_validator('email')
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower()
```

### Don't Forget mode='json' for API Responses

```python
# WRONG - datetime not JSON-serializable
return user.model_dump()  # Returns datetime objects

# CORRECT
return user.model_dump(mode='json')  # Returns ISO strings
```

### Don't Use Optional Without Default

```python
# WRONG - Optional doesn't add a default!
class User(BaseModel):
    nickname: Optional[str]  # Still required!

# CORRECT
class User(BaseModel):
    nickname: str | None = None  # Now optional
```

---

## Performance Optimization

### Precompile Models with Large Field Counts

For models with 50+ fields, validation overhead stacks up:

```python
# Reduce overhead by disabling extra checks
class LargeModel(BaseModel):
    model_config = ConfigDict(
        validate_assignment=False,  # Don't re-validate on setattr
        validate_default=False,  # Skip default value validation
    )
```

### Use model_construct for Trusted Data

Skip validation entirely when data is already validated (e.g., from database):

```python
# Slow: full validation
user = UserResponse(**db_row)

# Fast: no validation
user = UserResponse.model_construct(**db_row)
```

**Warning:** Only use with 100% trusted data. One bad field corrupts your model.

### Cache TypeAdapters

Creating `TypeAdapter` instances is expensive. Cache them:

```python
from functools import lru_cache

@lru_cache
def get_adapter(type_: type) -> TypeAdapter:
    return TypeAdapter(type_)

# Reuse adapter
adapter = get_adapter(list[int])
adapter.validate_python([1, 2, 3])
```

---

## Migration Checklist from v1

If you're migrating existing code:

- [ ] Replace `.dict()` with `.model_dump()`
- [ ] Replace `.json()` with `.model_dump_json()`
- [ ] Replace `@validator` with `@field_validator`
- [ ] Replace `Config` class with `ConfigDict`
- [ ] Replace `orm_mode=True` with `from_attributes=True`
- [ ] Update `root_validator` to `@model_validator`
- [ ] Check for `Optional` without defaults
- [ ] Add `mode='json'` where needed for serialization
- [ ] Review discriminated unions for performance
- [ ] Test strict mode on critical endpoints

---

## Conclusion

Pydantic v2's Rust core and redesigned API make it the definitive choice for FastAPI data validation in 2025. The migration from v1 requires learning new patterns—`Annotated` types, validator modes, explicit serialization—but the performance gains and improved type safety justify the investment.

Focus on these production-critical patterns:
1. Use `Annotated` for reusable validation logic
2. Separate request/response schemas (never share models)
3. Apply discriminated unions to speed up polymorphic validation
4. Choose `mode='json'` for API responses, `mode='python'` for internal processing
5. Use `from_attributes=True` when working with ORMs

The v1 → v2 transition is a one-way door. The old patterns won't receive new features, and some are already deprecated. Build new applications on v2 patterns from day one.
