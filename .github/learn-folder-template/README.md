# Learn Folder Template

This directory contains templates for creating consistent, high quality educational documentation for each project.

## What Goes in a learn/ Folder

Every completed project should have a `learn/` directory with these four files:

1. **00-OVERVIEW.md** - Project introduction, prerequisites, quick start
2. **01-CONCEPTS.md** - Security concepts and theory
3. **02-ARCHITECTURE.md** - System design and technical decisions
4. **03-IMPLEMENTATION.md** - Code walkthrough and how to build it
5. **04-CHALLENGES.md** - Extension ideas and next steps

## Using These Templates

### For New Projects

When you start a new project:

1. Copy this entire template directory to your project:
   ```bash
   cp -r .github/learn-folder-template PROJECTS/[difficulty]/[project-name]/learn
   cd PROJECTS/[difficulty]/[project-name]/learn
   ```

2. Remove this README (you don't need it in the project):
   ```bash
   rm README.md
   ```

3. Fill in each template:
   - Replace `[placeholders]` with actual content
   - Delete sections that don't apply
   - Add sections specific to your project
   - Keep the overall structure

4. Write as you build - don't wait until the end

### For Existing Projects

Backfilling learn/ folders:

1. Start with 00-OVERVIEW.md - this is the easiest
2. Then do 01-CONCEPTS.md - what security ideas does this teach?
3. Then 02-ARCHITECTURE.md - how is it designed?
4. Then 03-IMPLEMENTATION.md - walk through the actual code
5. Finally 04-CHALLENGES.md - how can others extend it?

Don't try to do all files at once. One file per session works fine.

## Writing Guidelines

### Tone and Style

**Do:**
- Write like you're explaining to a smart friend
- Use concrete examples and real code
- Explain WHY, not just WHAT
- Reference actual vulnerabilities and incidents
- Show common mistakes and how to avoid them
- Use diagrams and code snippets liberally

**Don't:**
- Sound like a marketing brochure
- Use buzzwords without explaining them
- Assume the reader knows everything (or nothing)
- Write walls of text - break it up
- Skip the hard parts

### Content Depth

**00-OVERVIEW.md** - Surface level, get them excited and oriented
- 5-10 minute read
- Focus on what and why
- Light on technical details

**01-CONCEPTS.md** - Medium depth, teach the theory
- 15-20 minute read
- Explain security concepts thoroughly
- Use examples and diagrams
- Reference standards (OWASP, MITRE, etc)

**02-ARCHITECTURE.md** - Deep dive on system design
- 20-30 minute read
- Show the big picture
- Explain design decisions and tradeoffs
- Include diagrams

**03-IMPLEMENTATION.md** - Deepest, actual code walkthrough
- 30-45 minute read
- Reference real files and line numbers
- Show actual code from the project
- Explain step by step

**04-CHALLENGES.md** - Mixed depth based on difficulty
- 10-15 minute read
- Range from easy to expert
- Provide hints, not full solutions
- Encourage experimentation

### Code Examples

Always show real code from the actual project, not toy examples:

```python
# Good - actual code from the project
# src/auth/service.py:42-56
async def authenticate_user(email: str, password: str) -> User:
    user = await user_repo.find_by_email(email)
    if not user or not verify_password(password, user.password_hash):
        raise InvalidCredentials()
    return user
```

```python
# Bad - generic example
def login(username, password):
    # check if valid
    return user
```

### Avoiding AI Voice

Watch out for these telltale AI patterns:

**Em dashes** - Don't use them. Use periods or commas instead.
```
Bad: "It's not just about security — it's about building robust systems"
Good: "This teaches security and system design"
```

**Contrast flips** - The "it's not X, it's Y" pattern
```
Bad: "It's not about memorizing syntax — it's about understanding concepts"
Good: "Focus on understanding concepts, not memorizing syntax"
```

**Perfect hyphenation** - Don't hyphenate every compound modifier
```
Bad: "real-time analysis using state-of-the-art machine-learning algorithms"
Good: "real-time analysis using state of the art machine learning algorithms"
```

Mix it up. Sometimes hyphenate, sometimes don't. Humans are inconsistent.

**Generic enthusiasm**
```
Bad: "Embark on an exciting journey into the world of cybersecurity!"
Good: "Learn how rate limiting works by building one from scratch"
```

### Diagrams

ASCII diagrams work great:

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│     API     │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Database   │
└─────────────┘
```

Use them for:
- Architecture overviews
- Data flow
- State machines
- Layer diagrams

### Real World References

Ground concepts in reality:

**Good:**
"In the 2017 Equifax breach, attackers exploited a known Apache Struts vulnerability (CVE-2017-5638). This project teaches you how to scan for such vulnerabilities in your dependencies."

**Bad:**
"In today's evolving threat landscape, vulnerability management is critical."

## Quality Checklist

Before submitting a learn/ folder, check:

### 00-OVERVIEW.md
- [ ] Explains what the project does in 2-3 sentences
- [ ] Lists specific prerequisites with examples
- [ ] Includes quick start instructions that work
- [ ] Shows expected output
- [ ] Links to other learn/ files

### 01-CONCEPTS.md
- [ ] Explains each security concept thoroughly
- [ ] Includes real world examples or breaches
- [ ] Shows common attacks and defenses
- [ ] References OWASP/MITRE/CWE where relevant
- [ ] Includes "testing your understanding" questions

### 02-ARCHITECTURE.md
- [ ] High level architecture diagram
- [ ] Component breakdown
- [ ] Design decisions with reasoning
- [ ] Data flow examples
- [ ] Performance and security considerations

### 03-IMPLEMENTATION.md
- [ ] References actual files and line numbers
- [ ] Shows real code from the project
- [ ] Explains WHY, not just WHAT
- [ ] Includes common pitfalls
- [ ] Provides debugging tips

### 04-CHALLENGES.md
- [ ] Mix of difficulty levels
- [ ] Specific, actionable challenges
- [ ] Hints without full solutions
- [ ] Real world applications
- [ ] Connection to other projects

### General
- [ ] No em dashes
- [ ] Minimal "it's not X, it's Y" patterns
- [ ] Inconsistent hyphenation (like a human)
- [ ] Concrete examples, not abstractions
- [ ] Code examples are real, not toys
- [ ] Diagrams where helpful
- [ ] Links work
- [ ] Formatting is consistent

## Examples

Good examples to reference:

- **PROJECTS/advanced/bug-bounty-platform/learn/** - Comprehensive, well structured
- **PROJECTS/advanced/api-rate-limiter/learn/** - Good technical depth

These aren't perfect but they're solid templates to learn from.

## Getting Help

Questions about writing learn/ docs?

1. Look at existing examples
2. Ask in discussions
3. Draft one file and get feedback before doing all five
4. Iterate based on feedback

## Contributing Improvements

Found ways to improve these templates?

1. Make changes to `.github/learn-folder-template/`
2. Submit PR with explanation
3. Update this README if structure changes

The templates should evolve as we learn what works best.
