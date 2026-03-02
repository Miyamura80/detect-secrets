# ANSI color codes
GREEN=\033[0;32m
YELLOW=\033[0;33m
RED=\033[0;31m
BLUE=\033[0;34m
RESET=\033[0m

PROJECT_ROOT=.

.DEFAULT_GOAL := help

########################################################
# Help
########################################################

### Help
.PHONY: help
help: ## Show this help message
	@echo "$(BLUE)Available Make Targets$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "; category=""} \
		/^### / {category = substr($0, 5); next} \
		/^[a-zA-Z_-]+:.*?## / { \
			if (category != last_category) { \
				if (last_category != "") print ""; \
				print "$(GREEN)" category ":$(RESET)"; \
				last_category = category; \
			} \
			printf "  $(YELLOW)%-23s$(RESET) %s\n", $1, $2 \
		}' $(MAKEFILE_LIST)

########################################################
# Tauri / Frontend
########################################################

### Tauri
.PHONY: dev build tauri-dev tauri-build

dev: ## Run the frontend in development mode
	bun run dev

build: ## Build the frontend
	bun run build

tauri-dev: ## Run the app in Tauri development mode
	bun run tauri dev

tauri-build: ## Build the Tauri application
	bun run tauri build

docs: ## Run docs with bun
	@echo "$(GREEN)📚Running docs...$(RESET)"
	@cd docs && bun run dev
	@echo "$(GREEN)✅ Docs run completed.$(RESET)"


########################################################
# Initialization
########################################################

### Initialization
.PHONY: setup init banner logo

setup: ## Set up dev environment from scratch (installs deps, copies .env, checks tooling)
	@echo "$(BLUE)🔧 Setting up dev environment...$(RESET)"
	@if ! command -v rustup > /dev/null 2>&1; then \
		echo "$(RED)Error: rustup not found. Install from https://rustup.rs$(RESET)"; exit 1; \
	fi
	@rustup show > /dev/null 2>&1
	@echo "$(GREEN)✅ Rust toolchain ready$(RESET)"
	@if ! command -v bun > /dev/null 2>&1; then \
		echo "$(RED)Error: bun not found. Install from https://bun.sh$(RESET)"; exit 1; \
	fi
	@bun install
	@echo "$(GREEN)✅ Node dependencies installed$(RESET)"
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(YELLOW)⚠️  Copied .env.example → .env (fill in API keys before running)$(RESET)"; \
	else \
		echo "$(GREEN)✅ .env already exists$(RESET)"; \
	fi
	@echo "$(GREEN)✅ Setup complete. Run 'make tauri-dev' to start.$(RESET)"

init: ## Initialize project (usage: make init name=my-project description="my description")
	@if [ -z "$(name)" ] || [ -z "$(description)" ]; then \
		echo "$(RED)Error: Both 'name' and 'description' parameters are required$(RESET)"; \
		echo "Usage: make init name=<project_name> description=<project_description>"; \
		exit 1; \
	fi
	@echo "$(YELLOW)🚀 Initializing project $(name)...$(RESET)"
	@sed -i.bak "s/\"name\": \"tauri-app\"/\"name\": \"$(name)\"/" package.json && rm package.json.bak
	@sed -i.bak "s/\"productName\": \"tauri-app\"/\"productName\": \"$(name)\"/" src-tauri/tauri.conf.json && rm src-tauri/tauri.conf.json.bak
	@sed -i.bak "s/\"identifier\": \"com.eito.tauri-app\"/\"identifier\": \"com.$(USER).$(name)\"/" src-tauri/tauri.conf.json && rm src-tauri/tauri.conf.json.bak
	@sed -i.bak "s/name = \"tauri-app\"/name = \"$(name)\"/" src-tauri/Cargo.toml && rm src-tauri/Cargo.toml.bak
	@sed -i.bak "s/# Tauri-Template/# $(name)/" README.md && rm README.md.bak
	@sed -i.bak "s/<b>agent ready tauri template<\/b>/<b>$(description)<\/b>/" README.md && rm README.md.bak
	@echo "$(GREEN)✅ Updated project name, identifier, and description.$(RESET)"

### Asset Generation
.PHONY: banner logo

banner: ## Generate project banner image (requires APP__GEMINI_API_KEY)
	@echo "$(YELLOW)🔍Generating banner...$(RESET)"
	@cd src-tauri && cargo run --bin asset-gen -- banner
	@echo "$(GREEN)✅Banner generated at media/banner.png$(RESET)"

logo: ## Generate logo, icons, and favicon (requires APP__GEMINI_API_KEY)
	@echo "$(YELLOW)🔍Generating logo and favicon...$(RESET)"
	@cd src-tauri && cargo run --bin asset-gen -- logo
	@echo "$(GREEN)✅Logo assets saved to docs/public/$(RESET)"



########################################################
# Run Tests
########################################################

### Testing
test: ## Run Rust tests
	@echo "$(GREEN)🧪Running Rust Tests...$(RESET)"
	cd src-tauri && cargo test
	@echo "$(GREEN)✅Rust Tests Passed.$(RESET)"

test_fast: ## Run fast tests (Rust)
	@echo "$(GREEN)🧪Running Fast Rust Tests...$(RESET)"
	cd src-tauri && cargo test
	@echo "$(GREEN)✅Fast Rust Tests Passed.$(RESET)"

test_slow: ## Run slow tests (Rust placeholder)
	@echo "$(YELLOW)⚠️ No slow Rust tests defined yet.$(RESET)"

test_nondeterministic: ## Run nondeterministic tests (Rust placeholder)
	@echo "$(YELLOW)⚠️ No nondeterministic Rust tests defined yet.$(RESET)"

test_flaky: ## Repeat fast tests to detect flaky tests
	@echo "$(GREEN)🧪Running Flaky Test Detection (3 runs)...$(RESET)"
	@cd src-tauri && for i in 1 2 3; do \
		echo "Run $$i..."; \
		cargo test || exit 1; \
	done
	@echo "$(GREEN)✅Flaky Test Detection Passed.$(RESET)"


########################################################
# Code Quality
########################################################

### Code Quality
.PHONY: fmt lint knip audit link-check ci

fmt: ## Format code with Biome and rustfmt
	@echo "$(YELLOW)✨ Formatting and linting with Biome...$(RESET)"
	bunx @biomejs/biome check --write --unsafe .
	@echo "$(YELLOW)✨ Formatting Rust code...$(RESET)"
	cd src-tauri && cargo fmt
	@echo "$(GREEN)✅ Formatting completed.$(RESET)"

lint: ## Lint code with Biome and Clippy
	@echo "$(YELLOW)🔍 Checking with Biome...$(RESET)"
	bunx @biomejs/biome check .
	@echo "$(YELLOW)🔍 Linting Rust code with Clippy...$(RESET)"
	cd src-tauri && cargo clippy -- -D warnings
	@echo "$(GREEN)✅ Linting completed.$(RESET)"

knip: ## Find unused files, dependencies, and exports
	@echo "$(YELLOW)🔍 Running Knip...$(RESET)"
	@bun install --force >/dev/null 2>&1 || true
	bun run knip
	@echo "$(GREEN)✅ Knip completed.$(RESET)"

audit: ## Audit dependencies for vulnerabilities
	@echo "$(YELLOW)🔍 Auditing frontend dependencies...$(RESET)"
	bun audit
	@echo "$(YELLOW)🔍 Auditing Rust dependencies...$(RESET)"
	@if command -v cargo-deny > /dev/null 2>&1; then \
		cd src-tauri && cargo deny check; \
	else \
		echo "$(YELLOW)⚠️ cargo-deny not installed. Skipping Rust audit.$(RESET)"; \
	fi
	@echo "$(GREEN)✅ Audit completed.$(RESET)"

link-check: ## Check for broken links in markdown files
	@echo "$(YELLOW)🔍 Checking links...$(RESET)"
	@if command -v lychee > /dev/null 2>&1; then \
		lychee .; \
	else \
		echo "$(YELLOW)⚠️ lychee not installed. Falling back to docs lint script...$(RESET)"; \
		cd docs && bun run lint:links; \
	fi
	@echo "$(GREEN)✅ Link check completed.$(RESET)"

ci: fmt lint knip audit link-check test ## Run all CI checks
	@echo "$(GREEN)✅ CI checks completed.$(RESET)"
