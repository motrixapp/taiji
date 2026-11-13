#!/usr/bin/env python3
"""Assemble a version-bound taiji sidecar and its resolved dependency licenses."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def license_files(package):
    root = Path(package["manifest_path"]).parent.resolve()
    candidates = set()
    if package.get("license_file"):
        candidates.add((root / package["license_file"]).resolve())
    for directory in (root, root / "LICENSES", root / "licenses"):
        if directory.is_dir():
            for item in directory.iterdir():
                if item.is_file() and item.name.lower().startswith(
                    ("license", "licence", "copying", "notice", "copyright")
                ):
                    candidates.add(item.resolve())
    return sorted(
        path for path in candidates if path.is_file() and root in path.parents
    )


def archive_sidecar(directory, destination):
    """Keep the platform directory in both ZIP and tar archives."""
    if destination.name.endswith(".zip"):
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(directory.iterdir()):
                archive.write(file, f"{directory.name}/{file.name}")
    elif destination.name.endswith(".tar.gz"):
        with tarfile.open(destination, "w:gz") as archive:
            archive.add(directory, arcname=directory.name)
    else:
        raise ValueError("Unsupported sidecar archive format")


def assemble(args):
    metadata = json.loads(
        run(
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            args.target,
        )
    )
    package = next(
        package for package in metadata["packages"] if package["name"] == "taiji"
    )
    version = args.version.removeprefix("v")
    if version != package["version"]:
        raise ValueError("Tag version does not match the taiji package version")
    revision = run("git", "rev-parse", "HEAD")
    dirty = bool(run("git", "status", "--porcelain", "--untracked-files=no"))
    if os.environ.get("GITHUB_ACTIONS") == "true" and dirty:
        raise ValueError("Release source tree must be clean")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    binary = Path(args.binary)
    shutil.copy2(binary, output / binary.name)
    if not binary.name.endswith(".exe"):
        (output / binary.name).chmod(0o755)
    root = Path(metadata["workspace_root"])
    shutil.copy2(root / "LICENSE", output / "COPYING")
    timestamp = int(
        os.environ.get("SOURCE_DATE_EPOCH")
        or run("git", "show", "-s", "--format=%ct", "HEAD")
    )
    manifest = {
        "version": version,
        "version_string": f"taiji/{version}",
        "git_sha": revision,
        "git_dirty": dirty,
        "build_time_utc": datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc
        ).isoformat(),
        "target": args.target,
        "platform": args.platform,
        "platform_layout": output.name,
        "rustc": run("rustc", "--version"),
        "profile": "release",
        "cargo_locked": True,
        "rustflags": "--remap-path-prefix=<repo>=/taiji"
        + (" -C target-feature=+crt-static -C link-arg=/STACK:8388608" if args.target.endswith("-windows-msvc") else ""),
    }
    (output / "VERSION.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    reachable = set()
    pending = [package["id"]]
    while pending:
        identity = pending.pop()
        if identity in reachable:
            continue
        reachable.add(identity)
        pending.extend(
            dependency["pkg"]
            for dependency in nodes[identity]["deps"]
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"])
        )
    packages = sorted(
        (package for package in metadata["packages"]
         if package.get("source") and package["id"] in reachable),
        key=lambda package: (package["name"], package["version"]),
    )
    inventory = [
        "# Third-party dependencies",
        "",
        "taiji is GPL-2.0-or-later; see COPYING.",
        "The locked build graph includes runtime and build dependencies; some are target-specific.",
        "Provided license and notice files are collected in THIRD-PARTY-LICENSES.txt.",
        "Known upstream omissions and their declared licenses/authors are explicitly recorded there.",
        "",
        "| Package | Version | Declared license | Source |",
        "| --- | --- | --- | --- |",
    ]
    texts = []
    supplements_root = root / "packaging" / "licenses"
    supplements = json.loads((supplements_root / "supplements.json").read_text())
    for dependency in packages:
        name, release = dependency["name"], dependency["version"]
        declared = dependency.get("license") or "See bundled license file"
        inventory.append(
            f"| {name} | {release} | {declared} | https://crates.io/crates/{name}/{release} |"
        )
        files = license_files(dependency)
        texts.append(f"\n{'=' * 72}\n{name}@{release}\nDeclared license: {declared}\n")
        if not files:
            additions = supplements.get(f"{name}@{release}")
            if not additions:
                raise ValueError(f"No license/notice text found for {name}@{release}")
            for addition in additions:
                texts.append(f"Source: {addition['source']}\n")
                if addition.get("upstreamMissingText"):
                    texts.append(addition["note"] + "\n")
                    texts.append(f"Package authors: {', '.join(dependency['authors'])}\n")
                else:
                    texts.append((supplements_root / addition["file"]).read_text() + "\n")
        base = Path(dependency["manifest_path"]).parent.resolve()
        for source in files:
            try:
                text = source.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = source.read_text(encoding="latin-1")
            texts.append(f"\n--- {source.relative_to(base)} ---\n{text}\n")
    (output / "THIRD-PARTY-NOTICES.md").write_text(
        "\n".join(inventory) + "\n", encoding="utf-8"
    )
    (output / "THIRD-PARTY-LICENSES.txt").write_text("\n".join(texts), encoding="utf-8")
    files = [
        binary.name,
        "VERSION.json",
        "COPYING",
        "THIRD-PARTY-NOTICES.md",
        "THIRD-PARTY-LICENSES.txt",
    ]
    (output / "SHA256SUMS").write_text(
        "".join(f"{digest(output / name)}  {name}\n" for name in files),
        encoding="utf-8",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for option in ("target", "platform", "binary", "output", "version"):
        parser.add_argument(f"--{option}", required=True)
    parser.add_argument("--archive")
    arguments = parser.parse_args()
    assemble(arguments)
    if arguments.archive:
        archive_sidecar(Path(arguments.output), Path(arguments.archive))
