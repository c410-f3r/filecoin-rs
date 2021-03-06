deps_wasm:
	cargo install wasm-pack --version 0.8.1
	cargo install cargo-watch

build_wasm:
	rm -rf signer-wasm/pkg/
	wasm-pack build --no-typescript --target nodejs signer-wasm/
	wasm-pack build --no-typescript --target browser --out-dir pkg/browser signer-wasm/
	cp package-signer-wasm.json signer-wasm/pkg/package.json

PACKAGE_NAME:="@zondax/filecoin-signer-wasm"

clean_wasm:
	rm -rf examples/wasm_node/node_modules || true
	rm -rf examples/wasm_browser/node_modules || true

link_wasm: build_wasm
	cd signer-wasm/pkg && yarn unlink  || true
	cd examples/wasm_node && yarn unlink $(PACKAGE_NAME) || true
	cd examples/wasm_browser && yarn unlink $(PACKAGE_NAME) || true

#	# Now use it in other places
	cd signer-wasm/pkg && yarn link
	cd examples/wasm_node && yarn link $(PACKAGE_NAME) && yarn install
	cd examples/wasm_browser && yarn link $(PACKAGE_NAME)

test_wasm_unit: build_wasm
	wasm-pack test --firefox --headless ./signer-wasm

test_wasm_node: link_wasm
	cd examples/wasm_node && yarn install && yarn run test

test_wasm_browser: link_wasm
	cd examples/wasm_browser && yarn install && yarn start

test_wasm: test_wasm_unit test_wasm_node

deps_rust:
	cargo install cargo-audit
	cargo install cargo-tree
	cargo install cargo-license
	cargo install cargo-outdated
	cargo install cargo-watch https
	cargo install sccache
	yarn install
	echo "Remember to add export RUSTC_WRAPPER=sccache to your environment."

deps: deps_wasm deps_rust

checks:
	cargo fmt -- --check
	cargo clippy --all-features
	cargo audit

hooks:
	git config core.hooksPath .githooks

# prepreprocess circleci config so it can be ran locally
# Usage example:
# make ci JOB=test_service
ci:
	circleci config process .circleci/config.yml > .circleci/tmp.yml
	circleci build -c .circleci/tmp.yml --job ${JOB}

docs_dev:
	yarn install
	yarn dev

# Run this to have live refreshing of rust docs
docs_rust_edit:
	cargo watch -s 'cargo doc && browser-sync start --ss target/doc -s target/doc --directory --no-open'

docs_build:
	yarn install
	yarn build
