# faradayd — developer Makefile.
#
# Thin wrappers over the commands the CI workflow (.github/workflows/sandbox-daemon-ci.yml)
# and the build plans (docs/wip/plan/02,03) already define. Run from this directory.
#
# Quick start:
#   make build            # debug build of all targets
#   make ci               # what CI runs: fmt-check + clippy + build + integration tests
#   make guest            # rebuild the wasm guest and re-pin its checksum

# wasm guest artefact and its integrity manifest (ADR-018).
GUEST_TARGET := wasm32-wasip1
GUEST_WASM   := guest/pysandbox-guest.wasm
GUEST_BUILT  := guest/target/$(GUEST_TARGET)/release/pysandbox-guest.wasm
CHECKSUMS    := CHECKSUMS.txt

# Local developer install (ADR-030/ADR-031). Mirrors the .pkg postinstall, but targets
# the current user and binary instead of the console user, so `make install` sets up the
# service on this dev machine without building a package.
LABEL        := dev.faraday.faradayd
BIN_SRC      := target/release/faradayd
BIN_DEST     ?= $(HOME)/.local/bin/faradayd
AGENTS_DIR   := $(HOME)/Library/LaunchAgents
LOG_DIR      := $(HOME)/Library/Logs
PLIST        := $(AGENTS_DIR)/$(LABEL).plist

# Demo configuration baked into the agent so the service runs after `make install`
# (examples/demo/.env.sample, absolute paths). Requires the demo's Docker services to be
# up (Dex on :5556 + the stub API) — see examples/demo/README.md. Mock-credential posture.
DEMO_DIR     := $(CURDIR)/examples/demo
COMPOSE      := examples/demo/docker-compose.yml
POLICY_PATH  := $(DEMO_DIR)/pysandbox.policy.json
AUDIT_KEY    := $(DEMO_DIR)/audit.key
OIDC_ISSUER  := http://127.0.0.1:5556/dex
OIDC_CLIENT  := faradayd
OIDC_SCOPES  := openid profile email
# Pinned guest digest, derived from CHECKSUMS.txt so it never drifts from the bundled wasm.
GUEST_DIGEST := $(shell grep '$(GUEST_WASM)' $(CHECKSUMS) | awk '{print $$1}')

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "} {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- Format & lint -----------------------------------------------------------

.PHONY: fmt
fmt: ## Format the workspace in place
	cargo fmt

.PHONY: fmt-check
fmt-check: ## Check formatting without writing (CI gate)
	cargo fmt --check

.PHONY: clippy
clippy: ## Lint all targets; warnings are errors (CI gate)
	cargo clippy --all-targets -- -D warnings

.PHONY: lint
lint: fmt-check clippy ## Run fmt-check and clippy

# --- Build -------------------------------------------------------------------

.PHONY: build
build: ## Debug build of all targets
	cargo build --all-targets

.PHONY: release
release: ## Optimised release build of the faradayd binary
	cargo build --release

# --- Test --------------------------------------------------------------------

.PHONY: test
test: ## Unit tests (no Docker required)
	cargo test

.PHONY: test-integration
test-integration: ## Full suite incl. integration tests (Docker required — RISK-003)
	cargo test --features integration

# --- WASM guest (RustPython) -------------------------------------------------

.PHONY: guest
guest: guest-build guest-checksum ## Rebuild the wasm guest and re-pin its checksum

.PHONY: guest-build
guest-build: ## Build the wasm32-wasip1 guest and copy it next to its manifest
	cd guest && cargo build --target $(GUEST_TARGET) --release
	cp $(GUEST_BUILT) $(GUEST_WASM)

.PHONY: guest-checksum
guest-checksum: ## Re-pin the guest sha256 into CHECKSUMS.txt
	@digest=$$(shasum -a 256 $(GUEST_WASM) | awk '{print $$1}'); \
	  { grep '^#' $(CHECKSUMS); echo "$$digest  $(GUEST_WASM)"; } > $(CHECKSUMS).tmp; \
	  mv $(CHECKSUMS).tmp $(CHECKSUMS); \
	  echo "re-pinned $(GUEST_WASM): $$digest"

.PHONY: checksum-verify
checksum-verify: ## Verify the guest artefact matches CHECKSUMS.txt (fail-closed)
	@grep -vE '^#|^[[:space:]]*$$' $(CHECKSUMS) | shasum -a 256 -c -

# --- Coverage ----------------------------------------------------------------
# Source-based coverage via cargo-llvm-cov (requires: cargo install cargo-llvm-cov
# and rustup component add llvm-tools-preview). Measures the full suite incl.
# integration tests, so Docker is required and the run is slow (~several minutes).

.PHONY: coverage
coverage: ## Print a coverage summary for the full suite (Docker required)
	cargo llvm-cov --features integration --summary-only

.PHONY: coverage-html
coverage-html: ## Generate an HTML coverage report under target/llvm-cov/html
	cargo llvm-cov --features integration --html
	@echo "report: target/llvm-cov/html/index.html"

.PHONY: coverage-lcov
coverage-lcov: ## Write an lcov.info report for CI / external tools
	cargo llvm-cov --features integration --lcov --output-path lcov.info
	@echo "wrote lcov.info"

# --- Supply chain & packaging ------------------------------------------------

.PHONY: deny
deny: ## Dependency advisory / licence gate (requires cargo-deny; ADR-018)
	cargo deny check

.PHONY: pkg
pkg: release ## Build the macOS .pkg installer (unsigned unless PYS_CODESIGN_IDENTITY is set)
	packaging/macos/build-pkg.sh

# --- Local developer install -------------------------------------------------
# Installs faradayd as a per-user launchd agent on this machine (macOS only).
# Everything runs as the current user: the binary lands in $(BIN_DEST) (default
# ~/.local/bin, user-writable, no sudo) and the agent, MCP registration, and load
# are all per-user.

.PHONY: install
install: release ## Install faradayd as a per-user launchd agent wired to the demo config (macOS; no sudo, installs to ~/.local/bin)
	@command -v launchctl >/dev/null 2>&1 || { echo "error: launchctl not found — make install targets macOS only" >&2; exit 1; }
	@test -n "$(GUEST_DIGEST)" || { echo "error: could not derive guest digest from $(CHECKSUMS)" >&2; exit 1; }
	mkdir -p "$(dir $(BIN_DEST))"
	install -m 755 "$(BIN_SRC)" "$(BIN_DEST)"
	mkdir -p "$(AGENTS_DIR)" "$(LOG_DIR)"
	@test -f "$(AUDIT_KEY)" || { head -c 32 /dev/urandom > "$(AUDIT_KEY)"; chmod 600 "$(AUDIT_KEY)"; echo "created audit key: $(AUDIT_KEY)"; }
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
	  '<plist version="1.0">' \
	  '<dict>' \
	  '  <key>Label</key><string>$(LABEL)</string>' \
	  '  <key>ProgramArguments</key><array><string>$(BIN_DEST)</string></array>' \
	  '  <key>EnvironmentVariables</key>' \
	  '  <dict>' \
	  '    <key>PYS_OIDC_ISSUER</key><string>$(OIDC_ISSUER)</string>' \
	  '    <key>PYS_OIDC_CLIENT_ID</key><string>$(OIDC_CLIENT)</string>' \
	  '    <key>PYS_OIDC_SCOPES</key><string>$(OIDC_SCOPES)</string>' \
	  '    <key>PYS_POLICY_PATH</key><string>$(POLICY_PATH)</string>' \
	  '    <key>PYS_GUEST_ARTIFACT_DIGEST</key><string>$(GUEST_DIGEST)</string>' \
	  '    <key>PYS_AUDIT_HMAC_KEY_REF</key><string>$(AUDIT_KEY)</string>' \
	  '    <key>PYS_ALLOW_PLAINTEXT_LOOPBACK_EGRESS</key><string>true</string>' \
	  '  </dict>' \
	  '  <key>RunAtLoad</key><true/>' \
	  '  <key>KeepAlive</key><true/>' \
	  '  <key>ProcessType</key><string>Background</string>' \
	  '  <key>StandardOutPath</key><string>$(LOG_DIR)/faradayd.out.log</string>' \
	  '  <key>StandardErrorPath</key><string>$(LOG_DIR)/faradayd.err.log</string>' \
	  '</dict>' \
	  '</plist>' > "$(PLIST)"
	plutil -lint "$(PLIST)"
	"$(BIN_DEST)" install-mcp-config "$(HOME)/.claude.json" || \
	  echo "faradayd: MCP config merge skipped (run '$(BIN_DEST) install-mcp-config' manually)"
	launchctl bootout "gui/$$(id -u)/$(LABEL)" 2>/dev/null || true
	launchctl bootstrap "gui/$$(id -u)" "$(PLIST)"
	@command -v docker >/dev/null 2>&1 \
	  && { echo "starting demo services (Dex + stub API)…"; docker compose -f "$(COMPOSE)" up -d; } \
	  || echo "faradayd: docker not found — start the demo services manually before using python_sandbox: docker compose -f $(COMPOSE) up -d"
	@echo "installed $(LABEL); logs: $(LOG_DIR)/faradayd.{out,err}.log"

.PHONY: uninstall
uninstall: ## Stop and remove the faradayd launchd agent, binary, and demo services (macOS; no sudo)
	launchctl bootout "gui/$$(id -u)/$(LABEL)" 2>/dev/null || true
	rm -f "$(PLIST)"
	rm -f "$(BIN_DEST)"
	@command -v docker >/dev/null 2>&1 \
	  && { echo "stopping demo services (Dex + stub API)…"; docker compose -f "$(COMPOSE)" down; } \
	  || echo "faradayd: docker not found — stop the demo services manually: docker compose -f $(COMPOSE) down"
	@echo "uninstalled $(LABEL) (MCP config left untouched; edit $(HOME)/.claude.json to remove the entry)"

# --- Aggregate ---------------------------------------------------------------

.PHONY: ci
ci: fmt-check clippy build test-integration ## Reproduce the CI pipeline locally

.PHONY: clean
clean: ## Remove build artefacts (daemon and guest)
	cargo clean
	cd guest && cargo clean
