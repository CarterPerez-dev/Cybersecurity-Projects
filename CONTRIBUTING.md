# Contributing Guidelines

Thank you for your interest in contributing to this cybersecurity projects repository! I welcome full project implementations that provide educational value to the security community.

***Contact - [carterperez@certgames.com](mailto:carterperez@certgames.com)***

## Contributing a Full Project

### 1. Fork the Repository

Start by forking the repository to your GitHub account:

**Repository:** [https://github.com/CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects)

Click the **Fork** button in the top-right corner, then clone your fork locally:

```bash
git clone https://github.com/YOUR-USERNAME/Cybersecurity-Projects.git
cd Cybersecurity-Projects
```

### 2. Create Your Project Directory

Create a new directory in `/PROJECTS` with a descriptive, lowercase, hyphenated name.

**Naming Convention:**
- ✅ `reverse-shell-handler`
- ✅ `api-security-scanner`
- ✅ `encrypted-p2p-chat`
- ❌ `reverse_shell_handler` (no underscores)
- ❌ `reverse.shell.handler` (no dots)
- ❌ `reverseShellHandler` (no camelCase)
- ❌ `ReverseShellHandler` (no PascalCase)
- ❌ `Reverse-Shell-Handler` (no capital letters)

**Examples:**

| Project Name | Directory Name |
|-------------|----------------|
| Reverse Shell Handler | `reverse-shell-handler` |
| SIEM Dashboard | `siem-dashboard` |
| OAuth Token Analyzer | `oauth-token-analyzer` |
| AI Threat Detection | `ai-threat-detection` |

### 3. Project Structure

Ensure your project structure is coherent and uses **intuitive, idiomatic naming** that follows common developer conventions.

**Required:**
- `README.md` - Detailed documentation (see below)
- Complete source code
- Any necessary configuration files

**If applicable:**
- `.env.example` - Template for environment variables (never commit actual `.env` files)
- `examples/` - Usage examples for advanced projects
- `requirements.txt` or `pyproject.toml` - Python dependencies
- `package.json` - Node.js dependencies
- `docker-compose.yml` - Container orchestration
- `Dockerfile` - Container builds

**Example Structure:**
```
PROJECTS/
└── your-project-name/
    ├── README.md
    ├── .env.example
    ├── requirements.txt
    ├── docker-compose.yml
    ├── src/
    │   ├── __init__.py
    │   ├── main.py
    │   └── utils/
    ├── tests/
    └── examples/
```

### 4. Package Managers if using Python and or Node (Doesn't matter what you use for any other framework/libary/language though)

**Python:** Use [uv](https://github.com/astral-sh/uv) for dependency management. It's faster, better, and if you think pip or poetry is superior in 2026, you're simply not ready to contribute here. (I'm only slightly joking..... but use uv pls...)
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create venv and install deps
uv sync
```

**Node.js:** Use [pnpm](https://pnpm.io/) or [Bun](https://bun.sh/). npm is for people who enjoy watching progress bars.
```bash
# pnpm
pnpm install

# bun
bun install
```


### 5. README Requirements

Your project README should include:

- **Project Title & Description** - What does it do and why is it useful?
- **Features** - Key functionality and capabilities
- **Educational Value** - What will users learn from this project?
- **Prerequisites** - Required tools, versions, and dependencies
- **Installation** - Step-by-step setup instructions
- **Usage** - How to run and use the project with examples
- **Configuration** - Environment variables and settings explained
- **Architecture** (for complex projects) - How components interact
- **Security Considerations** - Any warnings or best practices
- **License** - Project licensing information

### 6. Code Quality Standards

**Linting & Type Checking:**

All Python code must pass the following tools (with reasonable ignores as needed):

```bash
# Linting
ruff check .
pylint your_module/

# Type checking
mypy your_module/
```

**Code Formatting:**

Format your code using the repository's custom YAPF configuration. Copy the [.style.yapf](https://github.com/CarterPerez-dev/Cybersecurity-Projects/blob/main/.style.yapf) file and place it in the root of your project directory.
```bash
yapf -i -r -vv your_project/
```

Don't have YAPF installed? 
```bash
# With uv (you're using uv, right?)
uv pip install yapf

# Or if you insist on being difficult
pip install yapf
```

More info: [YAPF Documentation](https://github.com/google/yapf)

**Security Best Practices:**
- No hardcoded secrets, API keys, or credentials
- Input validation and sanitization
- Proper error handling
- Secure defaults
- Dependencies from trusted sources
- No oudtated dependencies (prefferably the current stable version)

### 7. Full-Stack Projects

Building a full-stack application? Consider using this template as a starting point:

**[Fullstack Template](https://github.com/CarterPerez-dev/fullstack-template)** - A production-ready template with FastAPI, React, Docker, and more.

### 8. Submit a Pull Request

**Create a new branch:**
```bash
git checkout -b add-your-project-name
```

**Commit your changes with clear messages:**
```bash
git add .
git commit -m "Add your-project-name: brief description"
```

**Push to your fork:**
```bash
git push origin add-your-project-name
```

**Open a Pull Request:**

1. Navigate to the [original repository](https://github.com/CarterPerez-dev/Cybersecurity-Projects)
2. Click **Pull Requests** → **New Pull Request**
3. Click **compare across forks**
4. Select your fork and branch
5. Fill out the PR template completely:
   - Provide a clear description of your project
   - Check the appropriate boxes in the checklist
   - Link any related issues
   - Add any additional context reviewers should know

**PR Template Checklist:**
- [ ] Code follows existing style and conventions
- [ ] Project has been tested
- [ ] README documentation is complete
- [ ] No security vulnerabilities introduced
- [ ] Read and followed CONTRIBUTING.md guidelines

## General Guidelines

- **Keep it educational** - Focus on practical learning value
- **Keep it legal and ethical** - Only include projects that can be used responsibly
- **Test thoroughly** - Verify your code works before submitting
- **Write clear commit messages** - Describe what changed and why
- **Be responsive** - Address review feedback promptly

## Questions?

If you have questions about contributing or want to discuss a project idea before starting, [open an issue](https://github.com/CarterPerez-dev/Cybersecurity-Projects/issues) for discussion.
