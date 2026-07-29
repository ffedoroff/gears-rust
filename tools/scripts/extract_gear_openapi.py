#!/usr/bin/env python3
"""Extract per-gear OpenAPI subsets from the platform document.

`make openapi` produces one platform-wide document from the running example server
(`docs/api/api.json`). Gears listed in `config/openapi-gears.yaml` additionally publish a spec
covering only their own paths; this script generates those files so they cannot drift from the
code. Everything except a small hand-maintained preamble (title / description / tags) comes from
the platform document.

Usage (from the repository root):

    python3 tools/scripts/extract_gear_openapi.py               # regenerate every gear
    python3 tools/scripts/extract_gear_openapi.py --gear resource-group
    python3 tools/scripts/extract_gear_openapi.py --check       # verify, write nothing
    python3 tools/scripts/extract_gear_openapi.py --src /tmp/openapi.json

`--check` exits non-zero when a committed file differs from what the current platform document
would produce, which is what CI should run.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is present in the repo toolchain
    sys.exit("PyYAML is required: pip install pyyaml")

DEFAULT_SRC = "docs/api/api.json"
DEFAULT_REGISTRY = "config/openapi-gears.yaml"

HEADER = """\
# GENERATED — do not edit by hand.
#
# Source:     {src} (produced by `make openapi` from the running server)
# Registry:   {registry} (entry `{name}`)
# Preamble:   {preamble}
# Regenerate: make openapi-gears
"""

NON_DEFAULT_SRC_NOTE = """\
#
# NOTE: generated from a source other than {default} — that document could not be
# regenerated at the time (see the gear's DESIGN / open issues). Re-run `make openapi` followed by
# `make openapi-gears` once the platform document can be produced from the full gear set.
"""


class Dumper(yaml.SafeDumper):
    """Block-style strings and insertion-ordered mappings."""


def _dict_representer(dumper: yaml.Dumper, data: OrderedDict) -> yaml.Node:
    return dumper.represent_mapping("tag:yaml.org,2002:map", data.items())


def _str_representer(dumper: yaml.Dumper, data: str) -> yaml.Node:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


Dumper.add_representer(OrderedDict, _dict_representer)
Dumper.add_representer(str, _str_representer)


def collect_refs(node: object, acc: set[str]) -> None:
    """Collect every `#/components/schemas/NAME` reachable from `node`."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            acc.add(ref.rsplit("/", 1)[1])
        for value in node.values():
            collect_refs(value, acc)
    elif isinstance(node, list):
        for item in node:
            collect_refs(item, acc)


def schema_closure(paths: dict, all_schemas: dict) -> set[str]:
    """Every schema reachable from `paths`, transitively."""
    needed: set[str] = set()
    collect_refs(paths, needed)
    while True:
        grown = set(needed)
        for name in needed:
            collect_refs(all_schemas.get(name, {}), grown)
        if grown == needed:
            return needed
        needed = grown


def build_document(entry: dict, doc: dict, src: str, registry: str) -> tuple[str, str]:
    """Return (rendered file contents, one-line summary) for a single registry entry."""
    name = entry["name"]
    patterns = [re.compile(p) for p in entry["paths"]]
    preamble_path = Path(entry["preamble"])

    preamble = yaml.safe_load(preamble_path.read_text(encoding="utf-8")) or {}

    all_schemas = doc.get("components", {}).get("schemas", {})
    paths = {
        p: v for p, v in doc.get("paths", {}).items() if any(r.match(p) for r in patterns)
    }
    if not paths:
        sys.exit(f"[{name}] no matching paths in {src} — check the `paths` patterns")

    needed = schema_closure(paths, all_schemas)
    missing = sorted(n for n in needed if n not in all_schemas)
    if missing:
        sys.exit(f"[{name}] referenced schemas absent from {src}: {missing}")

    info = OrderedDict()
    info["title"] = preamble.get("title", f"{name} API")
    info["version"] = doc.get("info", {}).get("version", "1.0.0")
    if preamble.get("description"):
        info["description"] = preamble["description"]

    out = OrderedDict()
    out["openapi"] = doc.get("openapi", "3.1.0")
    out["info"] = info
    out["servers"] = preamble.get("servers") or doc.get("servers", [])
    if preamble.get("tags"):
        out["tags"] = preamble["tags"]
    out["paths"] = OrderedDict(sorted(paths.items()))

    components = OrderedDict()
    components["schemas"] = OrderedDict((n, all_schemas[n]) for n in sorted(needed))
    security_schemes = doc.get("components", {}).get("securitySchemes")
    if security_schemes:
        components["securitySchemes"] = security_schemes
    out["components"] = components

    # Keep the header free of machine-specific absolute paths: a source outside the repository
    # is recorded by name only, and the note below explains the situation.
    src_path = Path(src)
    try:
        display_src = src_path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        display_src = f"{src_path.name} (local run, outside the repository)"

    header = HEADER.format(
        src=display_src, registry=registry, name=name, preamble=preamble_path.as_posix()
    )
    if src_path != Path(DEFAULT_SRC):
        header += NON_DEFAULT_SRC_NOTE.format(default=DEFAULT_SRC)
    body = yaml.dump(
        out, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=100, indent=2
    )

    operations = sum(
        1
        for ops in paths.values()
        for m in ops
        if m in ("get", "put", "post", "delete", "patch", "head", "options")
    )
    summary = (
        f"{name}: {len(paths)} paths, {operations} operations, {len(needed)} schemas"
        f" -> {entry['out']}"
    )
    return header + "\n" + body, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--src", default=DEFAULT_SRC, help=f"default: {DEFAULT_SRC}")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY, help=f"default: {DEFAULT_REGISTRY}")
    parser.add_argument("--gear", action="append", help="limit to this gear (repeatable)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed files match the source; write nothing",
    )
    args = parser.parse_args()

    src_path = Path(args.src)
    if not src_path.exists():
        sys.exit(
            f"{args.src} not found — run `make openapi` first, from the repository root"
        )
    doc = json.loads(src_path.read_text(encoding="utf-8"))

    registry_path = Path(args.registry)
    if not registry_path.exists():
        sys.exit(f"{args.registry} not found")
    entries = (yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}).get("gears") or []

    if args.gear:
        wanted = set(args.gear)
        known = {e["name"] for e in entries}
        unknown = sorted(wanted - known)
        if unknown:
            sys.exit(f"unknown gear(s): {unknown}; registry has {sorted(known)}")
        entries = [e for e in entries if e["name"] in wanted]

    if not entries:
        print(f"no gears registered in {args.registry} — nothing to do")
        return 0

    stale: list[str] = []
    for entry in entries:
        rendered, summary = build_document(entry, doc, args.src, args.registry)
        out_path = Path(entry["out"])

        if args.check:
            current = out_path.read_text(encoding="utf-8") if out_path.exists() else ""
            if current == rendered:
                print(f"ok       {summary}")
                continue
            stale.append(entry["name"])
            print(f"STALE    {summary}")
            diff = difflib.unified_diff(
                current.splitlines(),
                rendered.splitlines(),
                fromfile=f"{out_path} (committed)",
                tofile=f"{out_path} (generated)",
                lineterm="",
                n=1,
            )
            for line in list(diff)[:40]:
                print(f"  {line}")
            continue

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        print(f"wrote    {summary}")

    if stale:
        print(
            f"\n{len(stale)} gear spec(s) out of date: {', '.join(stale)}\n"
            "Run `make openapi-gears` and commit the result."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
