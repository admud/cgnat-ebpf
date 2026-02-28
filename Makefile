.PHONY: all build build-ebpf build-user clean test

all: build

# Build everything
build: build-ebpf build-user

# Build eBPF program (requires nightly + bpf-linker)
build-ebpf:
	cd cgnat-ebpf && cargo +nightly build --release -Z build-std=core

# Build userspace program
build-user: build-ebpf
	cargo build --release -p cgnat

# Debug build
debug: debug-ebpf debug-user

debug-ebpf:
	cd cgnat-ebpf && cargo +nightly build -Z build-std=core

debug-user: debug-ebpf
	cargo build -p cgnat

# Clean build artifacts
clean:
	cargo clean
	cd cgnat-ebpf && cargo clean

# Run clippy
lint:
	cargo clippy -p cgnat -p cgnat-common -- -D warnings
	cd cgnat-ebpf && cargo +nightly clippy -Z build-std=core -- -D warnings

# Format code
fmt:
	cargo fmt --all
	cd cgnat-ebpf && cargo +nightly fmt

# Check formatting
fmt-check:
	cargo fmt --all -- --check
	cd cgnat-ebpf && cargo +nightly fmt -- --check

# Install dependencies
deps:
	rustup install nightly
	rustup component add rust-src --toolchain nightly
	cargo install bpf-linker

# Run (requires root)
run: build
	sudo ./target/release/cgnat $(ARGS)

# Example usage
example:
	@echo "Example: make run ARGS='run -e eth0 -i eth1 -E 203.0.113.1 -I 10.0.0.0/8'"

# ============================================================================
# Testing
# ============================================================================

# Set up test environment (requires root)
test-setup:
	sudo ./tests/setup_test_env.sh setup

# Clean up test environment (requires root)
test-cleanup:
	sudo ./tests/setup_test_env.sh cleanup

# Show test environment status
test-status:
	sudo ./tests/setup_test_env.sh status

# Run integration tests (requires test environment and CGNAT running)
test-integration:
	sudo ./tests/run_tests.sh all

# Run A/B performance benchmark (cgnat vs iptables vs nftables)
bench-compare: build
	sudo ./tests/bench_compare.sh

# Run benchmark with custom mode list
# Example: make bench-compare-modes MODES='cgnat,iptables'
bench-compare-modes: build
	@test -n "$(MODES)" || (echo "Usage: make bench-compare-modes MODES='cgnat,iptables'" && exit 1)
	sudo ./tests/bench_compare.sh --modes '$(MODES)'

# Run CGNAT in test environment
test-run: build
	@echo "Starting CGNAT in test namespace..."
	@echo "Press Ctrl+C to stop"
	sudo ip netns exec ns_cgnat ./target/release/cgnat run \
		-e veth_ext_a -i br_int -E 203.0.113.1 -I 10.0.0.0/24 --skb-mode

# Full test cycle
test: build test-setup
	@echo ""
	@echo "Test environment ready. In another terminal, run:"
	@echo "  make test-run"
	@echo ""
	@echo "Then in a third terminal, run:"
	@echo "  make test-integration"
	@echo ""
	@echo "When done, run:"
	@echo "  make test-cleanup"
