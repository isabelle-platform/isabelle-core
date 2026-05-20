#!/usr/bin/env python3
"""
Expand the Cargo.toml + main.rs shell templates for a given flavour.

Usage:
    tools/gen_shell.py <flavour> <core_path> <out_dir> <flavour_json>

Arguments:
    flavour       — flavour name, used for crate/binary names
    core_path     — relative path from <out_dir> to the core crate
    out_dir       — where to write Cargo.toml + src/main.rs
    flavour_json  — path to the flavour's plugin list JSON. The flavour
                    definitions live in release-generator/flavours/, not
                    in this repo, so the path is passed in explicitly.

Reads:
    <flavour_json>            — list of {name, url, tag} (or {name, url, branch})
    templates/Cargo.toml.tmpl
    templates/main.rs.tmpl

Writes:
    <out_dir>/Cargo.toml
    <out_dir>/src/main.rs

Placeholders in the templates:
    __FLAVOUR__              — the flavour name (e.g. "midair")
    __VERSION__              — the core crate's version (from core Cargo.toml)
    __CORE_PATH__            — relative path from <out_dir> to the core crate
    __PLUGIN_DEPS__          — `[dependencies]` lines for each plugin
    __PLUGIN_REGISTRATIONS__ — `register_actor` call per plugin, inside the
                               `isabelle_core::run` closure (4-space-indented
                               inside the closure's body)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def crate_ident(name: str) -> str:
    """Cargo crate name → Rust identifier (`-` becomes `_`)."""
    return name.replace("-", "_")


def core_version(core_cargo_toml: Path) -> str:
    """Read `[package] version` from the core crate's Cargo.toml — the
    single source of truth for the version stamped on shell crates."""
    in_package = False
    for line in core_cargo_toml.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_package = stripped == "[package]"
            continue
        if in_package and stripped.startswith("version"):
            # version = "1.23.0"
            return stripped.split("=", 1)[1].strip().strip('"')
    raise SystemExit(f"could not find [package] version in {core_cargo_toml}")


def render(
    flavour: str, core_path: str, version: str, plugins: list[dict]
) -> tuple[str, str]:
    repo_root = Path(__file__).resolve().parent.parent
    cargo_tmpl = (repo_root / "templates" / "Cargo.toml.tmpl").read_text()
    main_tmpl = (repo_root / "templates" / "main.rs.tmpl").read_text()

    dep_lines = []
    for p in plugins:
        name = p["name"]
        url = p["url"]
        if "tag" in p:
            ref = f'tag = "{p["tag"]}"'
        elif "branch" in p:
            ref = f'branch = "{p["branch"]}"'
        elif "rev" in p:
            ref = f'rev = "{p["rev"]}"'
        else:
            raise SystemExit(
                f"flavour entry {name}: needs one of tag/branch/rev"
            )
        dep_lines.append(f'{name} = {{ git = "{url}", {ref} }}')

    reg_lines = [
        f"        {crate_ident(p['name'])}::register_actor(reg, core.clone());"
        for p in plugins
    ]

    subs = {
        "__FLAVOUR__": flavour,
        "__VERSION__": version,
        "__CORE_PATH__": core_path,
        "__PLUGIN_DEPS__": "\n".join(dep_lines),
        "__PLUGIN_REGISTRATIONS__": "\n".join(reg_lines),
    }

    cargo = cargo_tmpl
    main = main_tmpl
    for k, v in subs.items():
        cargo = cargo.replace(k, v)
        main = main.replace(k, v)
    return cargo, main


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    flavour = sys.argv[1]
    core_path = sys.argv[2]
    out_dir = Path(sys.argv[3])
    flavour_json = Path(sys.argv[4])

    if not flavour_json.exists():
        print(f"error: no flavour file {flavour_json}", file=sys.stderr)
        return 1

    plugins = json.loads(flavour_json.read_text())
    if not isinstance(plugins, list):
        print(f"error: {flavour_json} must be a JSON array", file=sys.stderr)
        return 1

    # Core version comes from core's own Cargo.toml — `core_path` is
    # relative to `out_dir`, so resolve it against that.
    core_cargo = (out_dir / core_path / "Cargo.toml").resolve()
    if not core_cargo.exists():
        print(f"error: core Cargo.toml not found at {core_cargo}", file=sys.stderr)
        return 1
    version = core_version(core_cargo)

    cargo, main_rs = render(flavour, core_path, version, plugins)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "src").mkdir(parents=True, exist_ok=True)
    (out_dir / "Cargo.toml").write_text(cargo)
    (out_dir / "src" / "main.rs").write_text(main_rs)
    print(f"generated {out_dir}/Cargo.toml + src/main.rs ({len(plugins)} plugins)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
