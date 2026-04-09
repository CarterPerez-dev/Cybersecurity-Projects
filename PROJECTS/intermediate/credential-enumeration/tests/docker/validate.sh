#!/usr/bin/env bash
# ©AngelaMos | 2026
# validate.sh
#
# Docker-based integration test for all 7 collector categories
#
# Runs the credenum binary against planted test fixtures under
# /home/testuser and validates that every expected finding appears
# in the output. Captures JSON-format output into OUTPUT, then
# runs the terminal renderer for visual inspection. The check()
# helper greps the captured output for a case-insensitive pattern
# and tallies pass/fail counts.
#
# Validates 30 findings across all categories: ssh (unprotected
# key, encrypted key, weak config, authorized keys, known hosts),
# cloud (AWS static keys, AWS config, GCP service account,
# Kubernetes config), browser (Firefox logins, cookies, key
# database, Chromium login data), history (secret pattern, curl
# auth, sshpass, environment file), keyring (GNOME Keyring,
# KeePass database, password store), git (plaintext credentials,
# credential helper, GitHub token), apptoken (PostgreSQL, MySQL,
# Docker auth, netrc, npm, PyPI, GitHub CLI, Vault). Exits with
# code 1 if any check fails.
#
# Connects to:
#   credenum binary                - all 7 collector modules
#   tests/docker/Dockerfile        - fixture layout in /home/testuser

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local label="$1"
    local pattern="$2"
    if echo "$OUTPUT" | grep -qi "$pattern"; then
        echo -e "  ${GREEN}+${NC} $label"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}x${NC} $label"
        FAIL=$((FAIL + 1))
    fi
}

echo -e "\n${BOLD}Running credenum...${NC}\n"

OUTPUT=$(credenum --target /home/testuser --format json 2>&1) || true

echo -e "${BOLD}Terminal output:${NC}\n"
credenum --target /home/testuser 2>&1 || true

echo -e "\n${BOLD}Validating findings across all 7 categories...${NC}\n"

echo -e "${BOLD}[ssh]${NC}"
check "SSH unprotected private key"         "no passphrase"
check "SSH encrypted private key"           "passphrase-protected"
check "SSH config weak settings"            "PasswordAuthentication"
check "SSH authorized keys"                 "authorized public keys"
check "SSH known hosts"                     "known hosts"

echo -e "\n${BOLD}[cloud]${NC}"
check "AWS credentials with static keys"    "static keys"
check "AWS config profiles"                 "profiles"
check "GCP service account"                 "service_account"
check "Kubernetes config"                   "contexts"

echo -e "\n${BOLD}[browser]${NC}"
check "Firefox stored logins"               "Firefox stored logins"
check "Firefox cookies"                     "Firefox cookies"
check "Firefox key database"                "Firefox key"
check "Chromium login data"                 "google-chrome.*login"

echo -e "\n${BOLD}[history]${NC}"
check "History secret pattern"              "Secret in shell history"
check "Sensitive command (curl auth)"       "curl.*authoriz"
check "Sensitive command (sshpass)"         "sshpass"
check "Environment file"                    "Environment file"

echo -e "\n${BOLD}[keyring]${NC}"
check "GNOME Keyring"                       "GNOME Keyring"
check "KeePass database"                    "KeePass"
check "Password store"                      "password-store"

echo -e "\n${BOLD}[git]${NC}"
check "Git credentials plaintext"           "Plaintext Git credential"
check "Git credential helper"               "credential helper"
check "GitHub token"                        "GitHub.*token"

echo -e "\n${BOLD}[apptoken]${NC}"
check "PostgreSQL pgpass"                   "PostgreSQL"
check "MySQL config"                        "MySQL"
check "Docker registry auth"               "Docker.*auth"
check "Netrc credential file"              "Netrc credential"
check "npm auth token"                     "npm registry"
check "PyPI credentials"                   "PyPI.*credentials"
check "GitHub CLI OAuth token"             "GitHub CLI"
check "Vault token"                        "Vault token"

echo ""
echo -e "${BOLD}Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}VALIDATION FAILED${NC}"
    exit 1
fi

echo -e "${GREEN}ALL CHECKS PASSED${NC}"
