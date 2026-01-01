#!/usr/bin/env bash
# =============================================================================
# AngelaMos | 2025
# setup.sh
# =============================================================================
# Template setup script - run once when starting a new project from template
# Usage: ./scripts/setup.sh
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}→ $1${NC}"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT_DIR"

echo -e "${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║               Template Setup Script                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# Environment file
# =============================================================================
step "Setting up environment file"

if [[ -f .env ]]; then
    warn ".env already exists, skipping copy"
else
    if [[ -f .env.example ]]; then
        cp .env.example .env
        success "Copied .env.example → .env"

        info "Generating secure SECRET_KEY..."
        if command -v openssl &> /dev/null; then
            SECRET_KEY=$(openssl rand -base64 32)
        else
            SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        fi
        sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${SECRET_KEY}|" .env
        success "SECRET_KEY generated and set"

        info "Edit .env to customize your configuration"
    else
        error ".env.example not found!"
    fi
fi

# =============================================================================
# Project templates (CONTRIBUTING, LICENSE, etc.)
# =============================================================================
step "Moving project template files"

if [[ -d "$ROOT_DIR/docs/templates" ]]; then
    for file in "$ROOT_DIR/docs/templates"/*; do
        if [[ -f "$file" ]]; then
            filename=$(basename "$file")
            if [[ -f "$ROOT_DIR/$filename" ]]; then
                warn "$filename already exists in root, skipping"
            else
                mv "$file" "$ROOT_DIR/"
                success "Moved $filename → root"
            fi
        fi
    done
    info "Run 'just clean-templates' to remove docs/templates/ directory"
else
    warn "docs/templates/ not found, skipping"
fi

# =============================================================================
# Backend setup
# =============================================================================
step "Setting up backend"

if ! command -v uv &> /dev/null; then
    warn "uv not found, installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    success "uv installed"
fi

info "uv version: $(uv --version)"

cd "$ROOT_DIR/backend"

info "Creating venv and installing dependencies..."
uv sync
success "Backend dependencies installed"

if [[ -f .pre-commit-config.yaml ]]; then
    info "Installing pre-commit hooks..."
    uv run pre-commit install
    success "Pre-commit hooks installed"
fi

cd "$ROOT_DIR"

# =============================================================================
# Frontend setup
# =============================================================================
step "Setting up frontend"

if [[ -d "$ROOT_DIR/frontend" ]]; then
    cd "$ROOT_DIR/frontend"

    if ! command -v node &> /dev/null; then
        error "Node.js not found! Install Node.js 22+ first"
    fi

    info "Node version: $(node --version)"

    info "Enabling corepack for pnpm..."
    corepack enable 2>/dev/null || sudo corepack enable

    if ! command -v pnpm &> /dev/null; then
        info "Preparing pnpm..."
        corepack prepare pnpm@latest --activate
    fi

    info "pnpm version: $(pnpm --version)"

    info "Installing frontend dependencies..."
    pnpm install
    success "Frontend dependencies installed"

    cd "$ROOT_DIR"
else
    warn "frontend/ directory not found, skipping frontend setup"
    info "Create frontend/ and run this script again, or run manually:"
    info "  cd frontend && pnpm install"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${RED}"
cat << 'EOF'
⠀⠀⠀⠀⠀⠴⣦⣤⡀⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣨⣥⣄⣀⠀⡁⠀⠀⡀⡠⠀⠀⠀⠂⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣾⣿⣷⣮⣷⡦⠥⠈⡶⠮⣤⣀⡠⠀⡀⣐⣀⡈⠁⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⠟⠀⠠⠊⠉⠀⠀⢀⠉⠙⠚⠧⣦⣀⡀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠠⠀⠁⠀⢤⠀⠀⠀⠨⡉⠛⠶⠤⣄⣄⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⡀⠀⠀⢰⠀⠍⡾⠆⠀⠀⣠⡦⠄⡀⠄⠀⠠⠀⠀⠀⠈⠙⠓⠦⢤⣀⡀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣶⣦⢠⡈⠀⠀⠀⠀⠀⠋⠛⠉⡂⠈⠙⠀⣰⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠺⠦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠻⢿⣿⣿⣿⣿⣿⣾⣿⣿⣦⢤⡀⢀⣂⣨⠀⢅⢱⡔⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠲⠴⣠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣎⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣾⣽⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⠳⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠏⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠹⣦⣴⠖⠲⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠈⠀⠀⠀⠒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢩⠢⣙⠿⣿⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣆⠈⠛⢶⣌⡉⣻⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣷⣄⣤⣙⣿⣿⣿⣷⣄⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠛⠟⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⡿⣿⣿⣿⣿⣿⣿⡿⠋⠉⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠙⠁⠘⢮⣛⡽⠛⠿⡿⠥⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
EOF
echo -e "${NC}"
echo -e "${GREEN}${BOLD}               Setup Complete!${NC}"

echo -e "${GREEN}Next steps:${NC}"
echo ""
echo -e "  1. Edit .env with your configuration"
echo -e "     ${CYAN}vim .env${NC}"
echo ""
echo -e "  2. Start development environment"
echo -e "     ${CYAN}just dev-up${NC}"
echo ""
echo -e "  3. After creating models, run migrations"
echo -e "     ${CYAN}just migration-local \"initial\"${NC}"
echo -e "     ${CYAN}just migrate-local head${NC}"
echo ""
echo -e "${YELLOW}Tip:${NC} Run ${CYAN}just${NC} to see all available commands"
echo ""
