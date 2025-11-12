# CertGames Backend Makefile
# 2025 | ©AngelaMos


PYTHON := python

.DEFAULT_GOAL := dev

MAKEFLAGS += --no-print-directory

.PHONY: help dev install reinstall check fix mypy clean tree TODO pylint


define ASCII
	@echo "\033[35m"
	@echo " ⡋⣡⣴⣶⣶⡀⠄⠄⠙⢿⣿⣿⣿⣿⣿⣴⣿⣿⣿⢃⣤⣄⣀⣥⣿"
	@echo " ⢸⣇⠻⣿⣿⣿⣧⣀⢀⣠⡌⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣿⣿"
	@echo " ⢸⣿⣷⣤⣤⣤⣬⣙⣛⢿⣿⣿⣿⣿⣿⣿⡿⣿⣿⡍⠄⠄⢀⣤⣄⠉"
	@echo " ⣖⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⢇⣿⣿⡷⠶⠶⢿⣿⣿⠇⢀"
	@echo " ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣷⣶⣥⣴"
	@echo " ⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"
	@echo " ⣦⣌⣛⣻⣿⣿⣧⠙⠛⠛⡭⠅⠒⠦⠭⣭⡻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠄"
	@echo " ⣿⣿⣿⣿⣿⣿⣿⡆⠄⠄⠄⠄⠄⠄⠄⠄⠹⠈⢋⣽⣿⣿⣿⣿⣵⣾"
	@echo " ⣿⣿⣿⣿⣿⣿⣿⣿⠄⣴⣿⣶⣄⠄⣴⣶⠄⢀⣾⣿⣿⣿⣿⣿⣿⠃⠄⠄"
	@echo " ⠈⠻⣿⣿⣿⣿⣿⣿⡄⢻⣿⣿⣿⠄⣿⣿⡀⣾⣿⣿⣿⣿⣛⠛⠁"
	@echo " ⠄⠄⠈⠛⢿⣿⣿⣿⠁⠞⢿⣿⣿⡄⢿⣿⡇⣸⣿⣿⠿⠛⠁⠄"
	@echo " ⠄⠄⠄⠄⠄⠉⠻⣿⣿⣾⣦⡙⠻⣷⣾⣿⠃⠿⠋⠁⠄"
	@echo "\033[0m"
endef



help:
	@echo "\033[1;91mC\033[1;92me\033[1;93mr\033[1;94mt\033[1;95mG\033[1;96ma\033[1;91mm\033[1;92me\033[1;93ms\033[0m \033[1;94mBackend\033[0m \033[1;95mTesting\033[0m \033[1;96mCommands\033[0m"
	@echo "\033[1;5;93m==============================================\033[0m"
	@echo ""
	@echo "\033[1;4;96mSetup:\033[0m"
	@echo "  \033[92mmake \033[36minstall-dev\033[0m     \033[94m- Install development dependencies\033[0m"
	@echo "  \033[92mmake \033[36mreinstall\033[0m       \033[94m- Reinstall all dependencies with upgrades\033[0m"
	@echo ""
	@echo "\033[1;4;91mSyntax Checking (Ruff):\033[0m"
	@echo "  \033[92mmake \033[36mqa\033[0m           \033[94m- Check all code for syntax issues\033[0m"
	@echo "\033[1;4;91mSyntax Fixing (Ruff):\033[0m"
	@echo "  \033[92mmake \033[36mqa\033[0m           \033[94m- Fix all code of syntax issues\033[0m"	
	@echo ""
	@echo "\033[1;4;94mType Checking (mypy):\033[0m"
	@echo "  \033[92mmake \033[36mqa\033[0m            \033[94m- Type check all code\033[0m"
	@echo "\033[1;4;94mFormat:\033[0m"
	@echo "  \033[92mmake \033[36mqa\033[0m            \033[94m- Format code\033[0m"	
	@echo ""
	@echo "\033[1;4;92mUtilities:\033[0m"
	@echo "  \033[92mmake \033[36mclean\033[0m           \033[94m- Remove all cache files\033[0m"
	@echo "  \033[92mmake \033[36mtree\033[0m            \033[94m- Display the file tree\033[0m"
	@echo "  \033[92mmake \033[36mTODO\033[0m           \033[94m- Find All TODO \033[0m"	
	@echo ""
	@echo "\033[1;93mCurrent default domain: \033[1;5;95m$(DOMAIN)\033[0m"
	@echo ""
	@echo "\033[1;4;93mAvailable domains:\033[0m"
	@echo "  \033[91maccount\033[0m, \033[92mcommunity\033[0m, \033[93mcontent\033[0m, \033[94mfreemium\033[0m, \033[95mgames\033[0m,"
	@echo "  \033[96mmarketing\033[0m, \033[91mprogression\033[0m, \033[92mshop\033[0m, \033[93mtesting\033[0m, \033[94mtools\033[0m"
	@echo ""
		@echo "\033[95m ------------------------------"	
	@echo "\033[34m ⣿⣿⣿⡷⠊⡢⡹⣦⡑⢂⢕⢂⢕⢂⢕⢂⠕⠔⠌⠝⠛⠶⠶⢶⣦⣄⢂⢕⢂⢕"
		@echo "\033[34m ⣿⣿⠏⣠⣾⣦⡐⢌⢿⣷⣦⣅⡑⠕⠡⠐⢿⠿⣛⠟⠛⠛⠛⠛⠡⢷⡈⢂⢕⢂"
		@echo "\033[34m ⠟⣡⣾⣿⣿⣿⣿⣦⣑⠝⢿⣿⣿⣿⣿⣿⡵⢁⣤⣶⣶⣿⢿⢿⢿⡟⢻⣤⢑⢂"
		@echo "\033[36m ⣾⣿⣿⡿⢟⣛⣻⣿⣿⣿⣦⣬⣙⣻⣿⣿⣷⣿⣿⢟⢝⢕⢕⢕⢕⢽⣿⣿⣷⣔"
		@echo "\033[36m ⣿⣿⠵⠚⠉⢀⣀⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣗⢕⢕⢕⢕⢕⢕⣽⣿⣿⣿⣿"
		@echo "\033[36m ⢷⣂⣠⣴⣾⡿⡿⡻⡻⣿⣿⣴⣿⣿⣿⣿⣿⣿⣷⣵⣵⣵⣷⣿⣿⣿⣿⣿⣿⡿"
		@echo "\033[36m ⢌⠻⣿⡿⡫⡪⡪⡪⡪⣺⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃"
		@echo "\033[32m ⠣⡁⠹⡪⡪⡪⡪⣪⣾⣿⣿⣿⣿⠋⠐⢉⢍⢄⢌⠻⣿⣿⣿⣿⣿⣿⣿⣿⠏⠈"
		@echo "\033[32m ⡣⡘⢄⠙⣾⣾⣾⣿⣿⣿⣿⣿⣿⡀⢐⢕⢕⢕⢕⢕⡘⣿⣿⣿⣿⣿⣿⠏⠠⠈"
		@echo "\033[32m ⠌⢊⢂⢣⠹⣿⣿⣿⣿⣿⣿⣿⣿⣧⢐⢕⢕⢕⢕⢕⢅⣿⣿⣿⣿⡿⢋⢜⠠⠈"
		@echo "\033[95m ------------------------------"		
		@echo "\033[0m"





venv:
	@echo "Creating and initializing virtual environment in .venv..."
	@python3 -m venv .venv

# If you use bash, change @zsh
# can also run as just 'make'
dev:
	@zsh -c "source .venv/bin/activate && exec zsh"
	$(call ASCII)

# ==================== Setup ====================
install:
	@echo "Installing development dependencies..."
	pip install -e ".[dev]"

reinstall:
	@echo "Reinstalling all dependencies (including upgrades)..."
	pip install -e ".[dev]" --upgrade --upgrade-strategy eager
	$(call ASCII)


# ==================== Syntax Checking (Ruff) ====================
check:
	@echo "\033[1;3;4;96m======== Checking All Code ========\033[0m"
	@ruff check .
	$(call ASCII)

	
# ==================== Syntax Checking (Ruff) ====================
fix:
	@echo "\033[1;3;4;96m======== ruff fix All Code ========\033[0m"
	@ruff check . --fix
	$(call ASCII)
	

# ======================= In Depth Linting (pylint)=======================
pylint:
	@echo "\033[1;3;4;96m======== Linting All Code ========\033[0m"
	@pylint .
	$(call ASCII)
	
# ======================= Type Checking (mypy) =======================
mypy:
	@echo "\033[1;3;4;96m======== Type Checking All Code ========\033[0m"
	@mypy .
	$(call ASCII)


# ======================== Yapf Format =============================
format:
	@echo "\033[1;3;4;96m======== Formatting only qa/ ========\033[0m"
	@yapf -i -r -vv models/ repositories/ schemas/ scanners/ core/ factory/
	$(call ASCII)

# ==================== Utilities ====================
clean:
	@echo "\033[1;3;4;96m======== Cleaning Cache Files ========\033[0m"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
	$(call ASCII)

tree:
	@echo "\033[1;3;4;96m======== Creating Tree ========\033[0m"
	@tree -I 'node_modules|.git|*.log|dist|build|*.cache|certgames.egg-info|context|.venv|*.env|qa_context'
	$(call ASCII)
	
TODO:
	@echo "\033[1;3;4;96m======== Looking for TODO's ========\033[0m"
	@find . -name "*.py" -print0 | xargs -0 pylint --disable=all --enable=W0511 --msg-template='{path}:{line}:{column}: {msg_id}: {msg} ({symbol})' || true
	$(call ASCII)

