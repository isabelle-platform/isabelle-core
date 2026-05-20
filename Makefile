.PHONY: all build test clean-generated

# Usage:
#   make                       — plain core dev binary (no plugins)
#   make flavour=midair        — generated shell crate for the midair flavour
#   make flavour=cloudcpe      — same idea for any flavour
#
# Flavour definitions (plugin lists) live in the release-generator repo,
# not here. `flavours_dir` defaults to a sibling checkout; override it if
# your layout differs:
#   make flavour=midair flavours_dir=/path/to/release-generator/flavours
#
# Resulting binary for a flavour build:
#   generated/<flavour>/target/debug/isabelle-core-<flavour>
# Run it via:
#   BINARY=generated/<flavour>/target/debug/isabelle-core-<flavour> ./run.sh ...

flavour ?=
flavours_dir ?= ../release-generator/flavours

all: build

build:
ifeq ($(strip $(flavour)),)
	cargo build --bin isabelle-core
else
	python3 tools/gen_shell.py $(flavour) ../.. generated/$(flavour) $(flavours_dir)/$(flavour).json
	cargo build --manifest-path generated/$(flavour)/Cargo.toml
endif

test:
	cargo test --lib

clean-generated:
	rm -rf generated
