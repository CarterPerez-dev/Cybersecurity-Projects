# Implementation Guide

This document walks through the actual code. We'll build key features step by step and explain the decisions along the way.

## File Structure Walkthrough

```
[project-name]/
├── [directory]/
│   ├── [file1]     # [What this implements]
│   └── [file2]     # [What this implements]
├── [directory]/
│   └── [file]      # [What this implements]
└── [key file]      # [What this implements]
```

## Building [Core Feature 1]

### Step 1: [First Step]

What we're building: [Specific functionality]

Create `[filename]`:

```[language]
[Code with inline comments explaining the important parts]
```

**Why this code works:**
- [Line/section 1]: [Explanation of what it does and why]
- [Line/section 2]: [Explanation]
- [Line/section 3]: [Explanation]

**Common mistakes here:**
```[language]
# Wrong approach
[Code showing what NOT to do]

# Why this fails: [Explanation of the problem]
```

### Step 2: [Second Step]

Now we need to [next functionality].

In `[filename]` (lines XX-YY):

```[language]
[Relevant code snippet from the actual project]
```

**What's happening:**
1. [Step by step breakdown]
2. [Explanation]
3. [Explanation]

**Why we do it this way:**
[Explain the reasoning - performance, security, maintainability, etc]

**Alternative approaches:**
- [Approach A]: Works but [drawback]
- [Approach B]: Simpler but [limitation]

### Step 3: [Third Step]

[Continue pattern for each major step]

## Building [Core Feature 2]

### The Problem

[Describe what challenge this feature solves]

### The Solution

[High level approach before diving into code]

### Implementation

In `[filename]`:

```[language]
[Code implementation]
```

**Key parts explained:**

**[Function/class name]** (`[filename]:[line]`)
```[language]
[Focused code snippet]
```
This handles [specific responsibility]. The reason we [design choice] is because [explanation].

**[Another function/class]** (`[filename]:[line]`)
```[language]
[Code snippet]
```
[Explanation of what this does differently and why]

### Testing This Feature

```[language]
[Test code or example usage]
```

Expected output:
```
[What you should see]
```

If you see [error], it means [problem and fix].

## Security Implementation

### [Security Feature 1]

File: `[filename]`

```[language]
[Security related code]
```

**What this prevents:**
[Specific attack or vulnerability]

**How it works:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**What happens if you remove this:**
[Demonstrate why this security measure is necessary]

### [Security Feature 2]

[Same pattern for each security mechanism]

## Data Flow Example

Let's trace a complete request through the system.

**Scenario:** [Specific user action]

### Request Comes In

```[language]
# Entry point: [filename]:[line]
[Code at entry point]
```

At this point:
- [State/data description]
- [What's been validated]
- [What happens next]

### Processing Layer

```[language]
# Processing: [filename]:[line]
[Code in processing layer]
```

This code:
- [Action 1]
- [Action 2]
- [Why it's structured this way]

### Storage/Output

```[language]
# Final step: [filename]:[line]
[Code that completes the operation]
```

The result is [outcome]. We store/return it as [format] because [reason].

## Error Handling Patterns

### [Error Type 1]

When [condition] happens, we need to [response].

```[language]
# [filename]:[line]
try:
    [operation that might fail]
except [SpecificException] as e:
    [error handling]
```

**Why this specific handling:**
[Explanation of the error handling strategy]

**What NOT to do:**
```[language]
# Bad: catching everything
try:
    [operation]
except Exception:
    pass  # Silently fails - terrible idea
```

This hides actual problems. Always handle specific exceptions.

### [Error Type 2]

[Continue for major error cases]

## Performance Optimizations

### [Optimization 1]

**Before:**
```[language]
[Slow/naive implementation]
```

This was slow because [reason]. With [example scenario], it took [time/resources].

**After:**
```[language]
[Optimized implementation]
```

**What changed:**
- [Change 1]: [Impact]
- [Change 2]: [Impact]

**Benchmarks:**
- Before: [metric]
- After: [metric]
- Improvement: [percentage/factor]

### [Optimization 2]

[Same pattern]

## Configuration Management

### Loading Config

```[language]
# [filename]:[line]
[Config loading code]
```

**Why this approach:**
[Explain the config strategy]

**Validation:**
```[language]
[Config validation code if applicable]
```

We validate early because [reason]. If config is wrong, we want to fail fast at startup, not mysteriously later.

## Database/Storage Operations

### [Operation Type 1]

```[language]
# [filename]:[line]
[Database operation code]
```

**Important details:**
- [Transaction handling]: [Why it matters]
- [Connection management]: [How we avoid leaks]
- [Query optimization]: [Why we wrote it this way]

### Migrations

[If applicable]

When you change [data structure], run:
```bash
[migration command]
```

This updates [what changes] without losing [what's preserved].

## Integration Points

### [External System/API 1]

How we integrate with [system]:

```[language]
# [filename]:[line]
[Integration code]
```

**Authentication:**
[How auth is handled]

**Error handling:**
[What happens when external system fails]

**Rate limiting:**
[How we avoid getting throttled]

### [External System 2]

[Same pattern]

## Testing Strategy

### Unit Tests

Example test for [component]:

```[language]
# tests/[filename]
[Test code]
```

**What this tests:**
- [Behavior 1]
- [Behavior 2]

**Why these specific assertions:**
[Explain what could break and how test catches it]

### Integration Tests

```[language]
# tests/[filename]
[Integration test code]
```

This tests [end-to-end scenario]. We need this because unit tests don't catch [specific integration issues].

### Running Tests

```bash
[test command]
```

If tests fail with [error], check [common cause].

## Common Implementation Pitfalls

### Pitfall 1: [Common Mistake]

**Symptom:**
[What the developer sees]

**Cause:**
```[language]
# The problematic code
[What they probably wrote]
```

**Fix:**
```[language]
# Correct approach
[How to do it right]
```

**Why this matters:**
[Real impact of the mistake]

### Pitfall 2: [Another Mistake]

[Same pattern for common errors you actually see in this domain]

## Debugging Tips

### [Issue Type 1]

**Problem:** [Description]

**How to debug:**
1. Check [location 1] for [evidence]
2. Look at [logs/output] for [pattern]
3. Verify [assumption]

**Common causes:**
- [Cause 1]
- [Cause 2]

### [Issue Type 2]

[Continue for common debugging scenarios]

## Code Organization Principles

### Why [File/Module] is Structured This Way

```
[module]/
├── [file1]  # [Responsibility]
└── [file2]  # [Responsibility]
```

We separate [concern 1] from [concern 2] because:
- [Reason 1]
- [Reason 2]

This makes [benefit].

### Naming Conventions

- `[pattern]` = [What this naming means]
- `[pattern]` = [Convention explanation]

Following these patterns makes it easier to [benefit].

## Extending the Code

### Adding a New [Feature Type]

Want to add [capability]? Here's the process:

1. **Create [component]** in `[location]`
   ```[language]
   [Template code to start from]
   ```

2. **Register [component]** in `[location]`
   ```[language]
   [Registration code]
   ```

3. **Add tests** in `[location]`
   ```[language]
   [Test template]
   ```

### Plugin Pattern

[If applicable - how to extend without modifying core]

Create `plugins/[name].py`:
```[language]
[Plugin template code]
```

The system discovers plugins by [mechanism]. Your plugin must implement [interface].

## Code Style and Standards

### Formatting

We use [linter/formatter]:
```bash
[command to run it]
```

Key rules:
- [Rule 1]: [Why]
- [Rule 2]: [Why]

### Type Annotations

[If applicable]

```[language]
# Good
[properly typed code]

# Bad
[untyped code]
```

Types catch [specific bugs] at [development stage] instead of [runtime].

## Dependencies

### Why Each Dependency

- **[package1]** ([version]): [What we use it for, why this package specifically]
- **[package2]** ([version]): [Purpose and reasoning]
- **[package3]** ([version]): [Explanation]

### Dependency Security

Check for vulnerabilities:
```bash
[security scan command]
```

If you see [vulnerability type], [how to handle it].

## Build and Deploy

### Building

```bash
[build commands]
```

This produces [artifacts]. The build process:
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Local Development

```bash
# Start development environment
[dev command]

# Hot reload is enabled - changes to [files] reload automatically
```

### Production Deployment

[High level deployment process]

Key differences from dev:
- [Difference 1]
- [Difference 2]

## Performance Profiling

### Finding Bottlenecks

```bash
[profiling command]
```

Look for:
- [Metric 1] above [threshold] = [problem]
- [Metric 2] indicates [bottleneck]

### Memory Profiling

[If relevant]

```bash
[memory profiling command]
```

Common memory leaks in this codebase:
- [Pattern 1]: [How to spot and fix]
- [Pattern 2]: [Details]

## Next Steps

You've seen how the code works. Now:

1. **Try the challenges** - [04-CHALLENGES.md](./04-CHALLENGES.md) has extension ideas
2. **Modify the code** - Change [component] to [variation] to test your understanding
3. **Read related projects** - [Link to related project] builds on these concepts
