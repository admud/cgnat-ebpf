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

# Run clippy
lint:
	cargo clippy -p cgnat -p cgnat-common -- -D warnings
	cd cgnat-ebpf && cargo +nightly clippy -Z build-std=core -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

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
	@echo "Example: make run ARGS='-e eth0 -i eth1 -E 203.0.113.1 -I 10.0.0.0/8'"
