.PHONY: build midair midair-actor

all: midair

# Plain build: no plugin features. Useful for tests or non-deployment builds.
build:
	cargo build

# Midair deployment, trait-mode plugins (legacy, still works).
midair:
	cargo build --features midair

# Midair deployment, actor-mode plugins (security + midair through the actor
# pipeline; no global `plugin_pool` Mutex). This is the production target.
midair-actor:
	cargo build --features midair-actor
