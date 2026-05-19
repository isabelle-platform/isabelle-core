.PHONY: build midair

all: midair

# Plain build: no plugin features. Useful for tests or non-deployment builds.
build:
	cargo build

# Midair deployment: security + midair plugins (actor-mode, the only mode).
midair:
	cargo build --features midair
