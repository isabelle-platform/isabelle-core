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

# Room in the Mach-O header for the rpath `tools/fix_rpath.sh` stamps on after
# the link.
#
# A binary is linked with exactly the load commands it already has, and
# `install_name_tool` cannot grow that header afterwards: it refuses, the rpath
# of the native asp library never gets added, and the server aborts on the
# first run with "Library not loaded: @rpath/libasp.dylib — no LC_RPATH's
# found". The flag is Mach-O's own and means nothing to any other linker, so it
# is added on macOS only rather than unconditionally.
#
# Exported rather than passed per recipe so that it reaches cargo however this
# Makefile is entered. A caller that sets RUSTFLAGS on the command line — the
# midair-ts suite does — overrides this outright, so it has to carry the flag
# itself; it does.
ifeq ($(shell uname -s),Darwin)
export RUSTFLAGS := $(RUSTFLAGS) -C link-arg=-Wl,-headerpad_max_install_names
endif

all: build

build:
ifeq ($(strip $(flavour)),)
	cargo build --bin isabelle-core
else
	python3 tools/gen_shell.py $(flavour) ../.. generated/$(flavour) $(flavours_dir)/$(flavour).json
	cargo build --manifest-path generated/$(flavour)/Cargo.toml
	bash tools/fix_rpath.sh \
		generated/$(flavour)/target/debug/isabelle-core-$(flavour) \
		generated/$(flavour)/target/debug
endif

test:
	cargo test --lib

clean-generated:
	rm -rf generated
