#!/usr/bin/env python3
"""Package native release binaries; never include example identity/private keys."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=(
        "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
    ))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--check", action="store_true", help="Only check package versions")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=root, text=True,
    ))
    members = set(metadata["workspace_members"])
    versions = {p["version"] for p in metadata["packages"] if p["id"] in members}
    if len(versions) != 1 or args.tag != "v" + next(iter(versions)):
        parser.error(f"tag {args.tag!r} does not match workspace versions {sorted(versions)}")
    if args.check:
        print(f"All workspace packages match {args.tag}")
        return

    windows = args.target.endswith("windows-msvc")
    suffix = ".exe" if windows else ""
    binaries = Path(metadata["target_directory"]) / args.target / "release"
    name = f"kbshare-{args.tag}-{args.target}"
    output = root / "dist"
    output.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(tmp) / name
        bundle.mkdir()
        for binary in ("kbshare", "kbshare-registry", "kbshare-flow", "kbshare-config"):
            shutil.copy2(binaries / (binary + suffix), bundle / (binary + suffix))
        for document in ("README.md", "CHANGELOG.md"):
            shutil.copy2(root / document, bundle / document)
        (bundle / "examples").mkdir()
        shutil.copy2(root / "examples/config.json", bundle / "examples/config.json")
        shutil.copytree(root / "docs", bundle / "docs")
        if not windows:
            shutil.copytree(root / "packaging", bundle / "packaging")
        if windows:
            archive = output / (name + ".zip")
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                for path in sorted(bundle.rglob("*")):
                    if path.is_file():
                        handle.write(path, path.relative_to(tmp))
        else:
            archive = output / (name + ".tar.gz")
            with tarfile.open(archive, "w:gz") as handle:
                handle.add(bundle, arcname=name)
    print(archive)


if __name__ == "__main__":
    main()
