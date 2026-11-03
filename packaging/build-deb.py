#!/usr/bin/env python3
"""Build a native Debian package without installing anything on the host."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MAINTAINER = "moran1024a <moran1024a@gmail.com>"


def output(*command, cwd=ROOT):
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def install(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def dependency_notices(metadata):
    active = {node["id"] for node in metadata["resolve"]["nodes"]}
    sections = []
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["source"] is None or package["id"] not in active:
            continue
        directory = Path(package["manifest_path"]).parent
        files = {
            path for path in directory.rglob("*")
            if path.is_file() and re.fullmatch(r"(licen[cs]e|copying|notice)([.-].*)?", path.name, re.I)
        }
        if package["license_file"]:
            files.add(directory / package["license_file"])
        if not files:
            raise RuntimeError(f"Missing dependency license text: {package['name']}")
        sections.append(f"{package['name']} {package['version']} ({package['license']})\n")
        for path in sorted(files):
            sections.append(f"--- {path.relative_to(directory)} ---\n{path.read_text()}\n")
    return "\n".join(sections).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="use cached Cargo dependencies only")
    args = parser.parse_args()
    cargo = os.environ.get("CARGO", "cargo")
    flags = ["--locked"] + (["--offline"] if args.offline else [])
    host = next(line.split(": ", 1)[1] for line in output(cargo, "-vV").splitlines() if line.startswith("host: "))
    architecture = output("dpkg", "--print-architecture")
    expected_host = {"amd64": "x86_64-unknown-linux-gnu", "arm64": "aarch64-unknown-linux-gnu"}
    if expected_host.get(architecture) != host:
        raise RuntimeError("Build natively on amd64 or arm64 Debian/Ubuntu with the GNU Rust toolchain")

    subprocess.run([cargo, "build", "--release", "--target", host, *flags], cwd=ROOT, check=True)
    metadata = json.loads(output(cargo, "metadata", "--format-version", "1", "--filter-platform", host, *flags))
    package = next(p for p in metadata["packages"] if p["id"] == metadata["resolve"]["root"])
    name, version = package["name"], package["version"] + "-1"
    binary = Path(metadata["target_directory"]) / host / "release/netkeeper"
    artifact = ROOT / "dist" / f"{name}_{version}_{architecture}.deb"
    artifact.parent.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="netkeeper-deb-") as temporary:
        work = Path(temporary)
        staging = work / "package"
        control = staging / "DEBIAN"
        control.mkdir(parents=True)
        install(binary, staging / "usr/bin/netkeeper", 0o755)
        install(ROOT / "packaging/netkeeper.service", staging / "usr/lib/systemd/system/netkeeper.service")
        install(ROOT / "config.example.toml", staging / "etc/netkeeper/config.toml", 0o600)
        docs = staging / "usr/share/doc" / name
        install(ROOT / "README.md", docs / "README.md")
        install(ROOT / "LICENSE", docs / "copyright")
        (docs / "dependency-licenses.txt.gz").write_bytes(gzip.compress(dependency_notices(metadata), mtime=0))
        (docs / "dependency-licenses.txt.gz").chmod(0o644)
        for script in ("postinst", "prerm", "postrm"):
            install(ROOT / "packaging" / script, control / script, 0o755)
        (control / "conffiles").write_text("/etc/netkeeper/config.toml\n")

        # dpkg-shlibdeps needs source metadata to determine native library requirements.
        (work / "debian").mkdir()
        (work / "debian/control").write_text(
            f"Source: {name}\nMaintainer: {MAINTAINER}\n\n"
            f"Package: {name}\nArchitecture: any\nDescription: SRUN authentication service\n"
        )
        shared = output("dpkg-shlibdeps", "-O", "-e" + str(staging / "usr/bin/netkeeper"), cwd=work)
        shared = next(line.removeprefix("shlibs:Depends=") for line in shared.splitlines() if line.startswith("shlibs:Depends="))
        installed_size = (sum(p.stat().st_size for p in staging.rglob("*") if p.is_file()) + 1023) // 1024
        (control / "control").write_text(
            f"Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n"
            f"Maintainer: {MAINTAINER}\nSection: net\nPriority: optional\n"
            f"Depends: {shared}, systemd (>= 255), init-system-helpers (>= 1.56)\n"
            f"Installed-Size: {installed_size}\n"
            "Description: SRUN campus network authentication service\n"
            " Automatically authenticates and reconnects with optional interface binding.\n"
            " Configure /etc/netkeeper/config.toml and enable netkeeper.service after installation.\n"
        )
        checksums = []
        for path in sorted((staging / "usr").rglob("*")):
            if path.is_file():
                checksums.append(f"{hashlib.md5(path.read_bytes()).hexdigest()}  {path.relative_to(staging)}\n")
        (control / "md5sums").write_text("".join(checksums))
        for filename in ("control", "conffiles", "md5sums"):
            (control / filename).chmod(0o644)
        for directory in [staging, *[p for p in staging.rglob("*") if p.is_dir()]]:
            directory.chmod(0o755)
        (staging / "etc/netkeeper").chmod(0o700)
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(staging), str(artifact)], check=True)

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    artifact.with_suffix(".deb.sha256").write_text(f"{digest}  {artifact.name}\n")
    artifact.with_suffix(".deb.sha256").chmod(0o644)
    print(artifact)


if __name__ == "__main__":
    main()
