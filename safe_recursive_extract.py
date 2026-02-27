#!/usr/bin/env python3
import argparse
import gzip
import os
import shutil
import sys
import tarfile
from pathlib import Path
from typing import Set

TAR_EXTS = (".tar", ".tgz", ".tar.gz")
# plain .gz is handled separately (NOT .tar.gz)
def is_tarish(p: Path) -> bool:
    name = p.name.lower()
    return name.endswith(".tar") or name.endswith(".tgz") or name.endswith(".tar.gz")

def is_plain_gz(p: Path) -> bool:
    name = p.name.lower()
    return name.endswith(".gz") and not name.endswith(".tar.gz")

def unique_dir(base: Path) -> Path:
    if not base.exists():
        return base
    i = 1
    while True:
        cand = Path(f"{base}.{i}")
        if not cand.exists():
            return cand
        i += 1

def safe_member_path(dest_dir: Path, member_name: str) -> Path:
    """
    Compute the intended output path for a member, and ensure it stays within dest_dir.
    Blocks absolute paths and .. traversal.
    """
    # tar paths are posix-like
    # Reject absolute paths early
    if member_name.startswith("/") or member_name.startswith("\\"):
        raise ValueError(f"absolute member path: {member_name}")

    # Normalize and resolve against dest
    out_path = (dest_dir / member_name).resolve()

    # Ensure out_path is inside dest_dir
    dest_resolved = dest_dir.resolve()
    if dest_resolved == out_path or dest_resolved in out_path.parents:
        return out_path

    raise ValueError(f"path traversal outside dest: {member_name}")

def extract_tar_safely(archive: Path, dest_dir: Path, verbose: bool = True) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)

    # tarfile can open .tar, .tar.gz, .tgz automatically with mode "r:*"
    with tarfile.open(archive, mode="r:*") as tf:
        members = tf.getmembers()

        # Pre-validate member names for traversal/absolute paths
        for m in members:
            # TarInfo.name is the path inside archive
            try:
                _ = safe_member_path(dest_dir, m.name)
            except Exception as e:
                raise RuntimeError(f"Rejecting {archive}: {e}")

        # Extract only regular files + directories. Skip links/devices/fifos/etc.
        for m in members:
            # Skip symlinks and hardlinks and special files
            if m.issym() or m.islnk() or m.ischr() or m.isblk() or m.isfifo() or m.issock():
                if verbose:
                    print(f"      [skip special] {m.name}")
                continue

            # Ensure parent dirs exist; do manual extraction to avoid tarfile quirks
            out_path = safe_member_path(dest_dir, m.name)

            if m.isdir():
                out_path.mkdir(parents=True, exist_ok=True)
                continue

            if not m.isreg():
                # Unknown/other types: skip
                if verbose:
                    print(f"      [skip non-regular] {m.name}")
                continue

            out_path.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                # Sometimes tar marks a file but cannot provide data; skip
                if verbose:
                    print(f"      [skip unreadable] {m.name}")
                continue

            # Stream copy contents (do not preserve owner/perms)
            with src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst)

def gunzip_to_file(gz_path: Path, dest_dir: Path) -> Path:
    """
    Decompress a plain .gz into dest_dir/<basename_without_gz> (unique if needed).
    Returns output file path.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    base = gz_path.name
    if base.lower().endswith(".gz"):
        base = base[:-3]
    out = dest_dir / base
    if out.exists():
        out = Path(str(out))  # ensure Path
        i = 1
        while (Path(f"{out}.{i}")).exists():
            i += 1
        out = Path(f"{out}.{i}")

    with gzip.open(gz_path, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return out

def load_done(state_file: Path) -> Set[str]:
    if not state_file.exists():
        return set()
    return set(x.strip() for x in state_file.read_text(errors="ignore").splitlines() if x.strip())

def append_done(state_file: Path, item: str) -> None:
    with open(state_file, "a", encoding="utf-8") as f:
        f.write(item + "\n")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="Top-level archive (.tar/.tgz/.tar.gz/.gz)")
    ap.add_argument("output_dir", help="Output directory")
    ap.add_argument("--max-depth", type=int, default=8, help="Max nesting depth (default 8)")
    ap.add_argument("--quiet", action="store_true", help="Less output")
    args = ap.parse_args()

    inp = Path(args.input).expanduser()
    outdir = Path(args.output_dir).expanduser()
    max_depth = args.max_depth
    verbose = not args.quiet

    if not inp.is_file():
        print(f"Error: input file not found: {inp}", file=sys.stderr)
        return 1

    outdir.mkdir(parents=True, exist_ok=True)
    outdir = outdir.resolve()
    inp = inp.resolve()

    state = outdir / ".safe_recursive_extract.done"
    done = load_done(state)

    top = outdir / "top.extracted"
    top.mkdir(parents=True, exist_ok=True)

    def mark(path: Path):
        nonlocal done
        key = str(path.resolve())
        if key not in done:
            append_done(state, key)
            done.add(key)

    # Process top-level
    if str(inp) not in done:
        if is_tarish(inp):
            if verbose:
                print(f"[*] Extract top tar-ish: {inp} -> {top}")
            try:
                extract_tar_safely(inp, top, verbose=verbose)
            except Exception as e:
                print(f"[!] Top-level extract failed: {e}", file=sys.stderr)
                return 2
            mark(inp)
        elif is_plain_gz(inp):
            if verbose:
                print(f"[*] Gunzip top: {inp} -> {top}")
            try:
                gunzip_to_file(inp, top)
            except Exception as e:
                print(f"[!] Top-level gunzip failed: {e}", file=sys.stderr)
                return 2
            mark(inp)
        else:
            print(f"Error: unsupported input type: {inp}", file=sys.stderr)
            return 1

    # Recurse passes
    for depth in range(1, max_depth + 1):
        if verbose:
            print(f"[*] Pass {depth}/{max_depth}: scanning for nested archives...")

        candidates = []
        for p in outdir.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            if name.endswith(".tar") or name.endswith(".tgz") or name.endswith(".tar.gz") or name.endswith(".gz"):
                candidates.append(p)

        new_work = False

        for f in candidates:
            f = f.resolve()
            if str(f) in done:
                continue

            parent = f.parent
            if is_tarish(f):
                dest = unique_dir(parent / (f.name + ".extracted"))
                if verbose:
                    print(f"    [+] Extract: {f}")
                    print(f"        -> {dest}")
                try:
                    extract_tar_safely(f, dest, verbose=verbose)
                except Exception as e:
                    print(f"    [!] Skipped/rejected {f}: {e}", file=sys.stderr)
                mark(f)
                new_work = True

            elif is_plain_gz(f):
                dest = unique_dir(parent / (f.name + ".gunzipped"))
                if verbose:
                    print(f"    [+] Gunzip:  {f}")
                    print(f"        -> {dest}")
                try:
                    out_file = gunzip_to_file(f, dest)
                    # If it gunzips to a .tar, it’ll get picked up next pass automatically
                    if verbose:
                        print(f"        -> wrote {out_file.name}")
                except Exception as e:
                    print(f"    [!] Gunzip failed {f}: {e}", file=sys.stderr)
                mark(f)
                new_work = True

        if not new_work:
            if verbose:
                print("[*] No new archives found. Done.")
            break

    if verbose:
        print("[*] Extraction complete.")
        print(f"[*] Grep example:\n    grep -RIn --binary-files=without-match 'KEYWORD' '{outdir}'")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
