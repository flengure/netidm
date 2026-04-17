# Makefile for Netidm


CONTAINER_TOOL ?= docker
CONTAINER_TOOL_ARGS ?=
CONTAINER_BUILD_ARGS ?=
CONTAINER_IMAGE_BASE ?= netidm
CONTAINER_IMAGE_VERSION ?= devel
CONTAINER_IMAGE_EXT_VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "daemon")  | .version')
# CONTAINER_BUILDX_ACTION is used to specify the action for buildx, e.g., --push or --load
CONTAINER_BUILDX_ACTION ?= --push
# CONTAINER_IMAGE_ARCH is used to specify the architectures for multi-arch docker builds
CONTAINER_IMAGE_ARCH ?= "linux/amd64,linux/arm64"
BUILDKIT_PROGRESS ?= plain

NETIDM_FEATURES ?= ""

# MARKDOWN_FORMAT_ARGS is used to specify additional arguments for markdown formatting
MARKDOWN_FORMAT_ARGS ?=
BOOK_VERSION ?= master

GIT_COMMIT := $(shell git rev-parse HEAD)

.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.PHONY: config
config: ## Show makefile config things
config:
	@echo "CONTAINER_IMAGE_BASE: $(CONTAINER_IMAGE_BASE)"
	@echo "CONTAINER_IMAGE_VERSION: $(CONTAINER_IMAGE_VERSION)"
	@echo "CONTAINER_IMAGE_EXT_VERSION: $(CONTAINER_IMAGE_EXT_VERSION)"
	@echo "CONTAINER_TOOL: $(CONTAINER_TOOL)"
	@echo "CONTAINER_TOOL_ARGS: $(CONTAINER_TOOL_ARGS)"
	@echo "CONTAINER_BUILDX_ACTION: $(CONTAINER_BUILDX_ACTION)"
	@echo "CONTAINER_IMAGE_ARCH: $(CONTAINER_IMAGE_ARCH)"
	@echo "CONTAINER_BUILD_ARGS: $(CONTAINER_BUILD_ARGS)"
	@echo "MARKDOWN_FORMAT_ARGS: $(MARKDOWN_FORMAT_ARGS)"
	@echo "BUILDKIT_PROGRESS: $(BUILDKIT_PROGRESS)"
	@echo "BOOK_VERSION: $(BOOK_VERSION)"
	@echo "GIT_COMMIT: $(GIT_COMMIT)"

.PHONY: run
run: ## Run the test/dev server
run:
	cd server/daemon && ./run_insecure_dev_server.sh

.PHONY: run_htmx
run_htmx: ## Run in HTMX mode
run_htmx:
	cd server/daemon && KANI_CARGO_OPTS="--features netidmd_core/ui_htmx" ./run_insecure_dev_server.sh

.PHONY: buildx/netidmd
buildx/netidmd: ## Build multiarch netidm server images and push to docker hub
buildx/netidmd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f server/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "NETIDM_BUILD_PROFILE=container_generic" \
		--build-arg "NETIDM_FEATURES=$(NETIDM_FEATURES)" \
		--compress \
		--label "com.netidm.git-commit=$(GIT_COMMIT)" \
		--label "com.netidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/netidm_tools
buildx/netidm_tools: ## Build multiarch netidm tool images and push to docker hub
buildx/netidm_tools:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f tools/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/tools:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/tools:$(CONTAINER_IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "NETIDM_BUILD_PROFILE=container_generic" \
		--build-arg "NETIDM_FEATURES=$(NETIDM_FEATURES)" \
		--label "com.netidm.git-commit=$(GIT_COMMIT)" \
		--label "com.netidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/radiusd
buildx/radiusd: ## Build multi-arch radius docker images and push to docker hub
buildx/radiusd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f rlm_python/Dockerfile \
		--progress $(BUILDKIT_PROGRESS) \
		--label "com.netidm.git-commit=$(GIT_COMMIT)" \
		--label "com.netidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_EXT_VERSION) .

.PHONY: buildx
buildx: buildx/netidmd buildx/netidm_tools buildx/radiusd

.PHONY: build/netidmd
build/netidmd:	## Build the netidmd docker image locally
build/netidmd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION) \
		--build-arg "NETIDM_BUILD_PROFILE=container_generic" \
		--build-arg "NETIDM_FEATURES=" \
		--label "com.netidm.git-commit=$(GIT_COMMIT)" \
		--label "com.netidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/orca
build/orca:	## Build the orca docker image locally
build/orca:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f tools/orca/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/orca:$(CONTAINER_IMAGE_VERSION) \
		--build-arg "NETIDM_BUILD_PROFILE=container_generic" \
		--build-arg "NETIDM_FEATURES=$(NETIDM_FEATURES)" \
		--label "com.netidm.git-commit=$(GIT_COMMIT)" \
		--label "com.netidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/radiusd
build/radiusd:	## Build the radiusd docker image locally
build/radiusd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) \
		-f rlm_python/Dockerfile \
		--label "com.netidm.git-commit=$(GIT_COMMIT)" \
		--label "com.netidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) .

.PHONY: build
build: build/netidmd build/radiusd

.PHONY: test/netidmd
test/netidmd: ## Run cargo test in docker
test/netidmd:
	@$(CONTAINER_TOOL) build \
		$(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		--target builder \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION)-builder \
		--label "com.netidm.git-commit=$(GIT_COMMIT)" \
		--label "com.netidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) run --rm $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION)-builder cargo test

.PHONY: test/radiusd
test/radiusd: ## Run a test radius server
test/radiusd: build/radiusd
	cd rlm_python && \
	./run_radius_container.sh

.PHONY: test
test:
	cargo test

.PHONY: precommit
precommit: ## all the usual test things
precommit: test codespell test/pynetidm doc/format

.PHONY: vendor
vendor: ## Vendor required crates
vendor:
	cargo vendor > cargo_vendor_config

.PHONY: vendor-prep
vendor-prep: vendor
	tar -cJf vendor.tar.xz vendor

.PHONY: install-tools
install-tools: ## install netidm_tools in your local environment
install-tools:
	cargo install --path tools/cli --force

.PHONY: codespell
codespell: ## spell-check things.
codespell:
	codespell -c \
	-D .codespell_dictionary \
	--ignore-words .codespell_ignore \
	--skip='./target,./pynetidm/.venv,./pynetidm/.mypy_cache,./.mypy_cache,./pynetidm/uv.lock' \
	--skip='./book/*.js' \
	--skip='./book/book/*' \
	--skip='./book/src/images/*' \
	--skip='./docs/*,./.git' \
	--skip='*.svg' \
	--skip='*.br' \
	--skip='./rlm_python/mods-available/eap' \
	--skip='./server/lib/src/constants/system_config.rs' \
	--skip='./pynetidm/site'

.PHONY: test/pynetidm/pytest
test/pynetidm/pytest: ## python library testing
	cd pynetidm && \
	uv run pytest -vv

.PHONY: test/pynetidm/lint
test/pynetidm/lint: ## python library linting
	cd pynetidm && \
	uv run ruff check tests netidm

.PHONY: test/pynetidm/mypy
test/pynetidm/mypy: ## python library type checking
	cd pynetidm && \
	uv run mypy --strict tests netidm && \
	uv run ty check tests netidm \
		--ignore unused-type-ignore-comment

.PHONY: test/pynetidm
test/pynetidm: ## run the netidm python module test suite (mypy/lint/pytest)
test/pynetidm: test/pynetidm/pytest test/pynetidm/mypy test/pynetidm/lint

.PHONY: test/pynetidm/coverage
test/pynetidm/coverage: ## run the Netidm Python module test suite with coverage
	cd pynetidm && \
	uv run coverage run -m pytest && \
	uv run coverage html

########################################################################

.PHONY: doc
doc: ## Build the rust documentation locally
doc:
	cargo doc --document-private-items

.PHONY: doc/find
doc/find: ## Find all markdown files for docs
	@find . -type f  \
		-not -path './target/*' \
		-not -path './docs/*' \
		-not -path '*/node_modules/*' \
		-not -path '*/.venv/*' -not -path './vendor/*'\
		-not -path '*/.*/*' \
		-name '*.md'

.PHONY: doc/format
doc/format: ## Format docs and the Netidm book
	make doc/find | xargs deno fmt --check $(MARKDOWN_FORMAT_ARGS)

.PHONY: doc/format/fix
doc/format/fix: ## Fix docs and the Netidm book
	make doc/find | xargs  deno fmt  $(MARKDOWN_FORMAT_ARGS)

.PHONY: book
book: ## Build the Netidm book
book:
	echo "Building rust docs"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mv ./book/book/ ./docs/
	mkdir -p $(PWD)/docs/rustdoc/${BOOK_VERSION}/
	rsync -a --delete $(PWD)/target/doc/ $(PWD)/docs/rustdoc/${BOOK_VERSION}/

.PHONY: book_versioned
book_versioned:
	echo "Book version: ${BOOK_VERSION}"
	rm -rf ./target/doc
	git switch -c "${BOOK_VERSION}"
	git pull origin "${BOOK_VERSION}"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mkdir -p ./docs
	mv ./book/book/ ./docs/${BOOK_VERSION}/
	mkdir -p ./docs/${BOOK_VERSION}/rustdoc/
	mv ./target/doc/* ./docs/${BOOK_VERSION}/rustdoc/
	git switch master

.PHONY: clean_book
clean_book:
	rm -rf ./docs

.PHONY: docs/pynetidm/build
docs/pynetidm/build: ## Build the mkdocs
docs/pynetidm/build:
	cd pynetidm && \
	uv run --group docs mkdocs build

.PHONY: docs/pynetidm/serve
docs/pynetidm/serve: ## Run the local mkdocs server
docs/pynetidm/serve:
	cd pynetidm && \
	uv run --group docs mkdocs serve

########################################################################

.PHONY: release/prep
prep:
	cargo outdated -R
	cargo audit

.PHONY: release/netidm
release/netidm: ## Build the Netidm CLI - ensure you include the environment variable NETIDM_BUILD_PROFILE
	cargo build -p netidm_tools --bin netidm --release

.PHONY: release/netidmd
release/netidmd: ## Build the Netidm daemon - ensure you include the environment variable NETIDM_BUILD_PROFILE
	cargo build -p daemon --bin netidmd --release

.PHONY: release/netidm-ssh
release/netidm-ssh: ## Build the Netidm SSH tools - ensure you include the environment variable NETIDM_BUILD_PROFILE
	cargo build --release \
		--bin netidm_ssh_authorizedkeys \
		--bin netidm_ssh_authorizedkeys_direct

.PHONY: release/netidm-unixd
release/netidm-unixd: ## Build the Netidm UNIX tools - ensure you include the environment variable NETIDM_BUILD_PROFILE
release/netidm-unixd:
	cargo build -p pam_netidm --release
	cargo build -p nss_netidm --release
	cargo build --features unix -p netidm_unix_int --release \
		--bin netidm_unixd \
		--bin netidm_unixd_tasks \
		--bin netidm-unix

# cert things

.PHONY: cert/clean
cert/clean: ## clean out the insecure cert bits
cert/clean:
	rm -f /tmp/netidm/*.pem
	rm -f /tmp/netidm/*.cnf
	rm -f /tmp/netidm/*.csr
	rm -f /tmp/netidm/ca.txt*
	rm -f /tmp/netidm/ca.{cnf,srl,srl.old}


.PHONY: coverage
coverage: ## Run the coverage tests using cargo-tarpaulin
	cargo tarpaulin --out Html
	@echo "Coverage file at file://$(PWD)/tarpaulin-report.html"


.PHONY: coveralls
coveralls: ## Run cargo tarpaulin and upload to coveralls
coveralls:
	cargo tarpaulin --coveralls $(COVERALLS_REPO_TOKEN)
	@echo "Coveralls repo information is at https://coveralls.io/github/netidm/netidm"


.PHONY: eslint
eslint: ## Run eslint on the UI javascript things
eslint: eslint/setup
	@echo "################################"
	@echo "   Running eslint..."
	@echo "################################"
	cd server/core && find ./static -name '*js' -not -path '*/external/*' -exec eslint "{}" \;
	@echo "################################"
	@echo "Done!"

.PHONY: eslint/setup
eslint/setup: ## Install eslint for the UI javascript things
	cd server/core && npm ci

.PHONY: prettier
prettier: ## Run prettier on the UI javascript things
prettier: eslint/setup
	@echo "   Running prettier..."
	cd server/core && npm run prettier
	@echo "Done!"

.PHONY: prettier/fix
prettier/fix: ## Run prettier on the UI javascript things and write back changes
prettier/fix: eslint/setup
	@echo "   Running prettier..."
	cd server/core && npm run prettier:fix
	@echo "Done!"

.PHONY: publish
publish: ## Publish to crates.io
publish:
	cargo publish -p sketching
	cargo publish -p scim_proto
	cargo publish -p netidm_build_profiles
	cargo publish -p netidm_proto
	cargo publish -p netidm_utils_users
	cargo publish -p netidm_lib_file_permissions
	cargo publish -p netidm_lib_crypto
	cargo publish -p netidm_client
	cargo publish -p netidm_tools

.PHONY: rust_container
rust_container: # Build and run a container based on the Linux rust base container, with our requirements included
rust_container:
	docker build --pull -t netidm_rust -f scripts/Dockerfile.devcontainer .
	docker run \
		--rm -it \
		--name netidm \
		--mount type=bind,source=$(PWD),target=/netidm -w /netidm netidm_rust:latest
