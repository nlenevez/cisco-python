#!/usr/bin/env bash
set -u
IFS=$'\n\t'

# Usage:
#   ./safe_recursive_extract_v3.sh input.tar.gz output_dir [max_depth]
#
# Supports: .tar .tgz .tar.gz and plain .gz
# Untrusted hardening:
#   - reject absolute paths and ../ traversal in tar member names
#   - extract into controlled directory
#   - remove symlinks/devices/fifos/sockets after extraction

INPUT="${1:-}"
OUTDIR="${2:-}"
MAX_DEPTH="${3:-8}"

if [[ -z "${INPUT}" || -z "${OUTDIR}" ]]; then
  echo "Usage: $0 <input.tar|.tgz|.tar.gz|.gz> <output_dir> [max_depth]" >&2
  exit 1
fi
if [[ ! -f "${INPUT}" ]]; then
  echo "Error: input file not found: ${INPUT}" >&2
  exit 1
fi

mkdir -p "${OUTDIR}"
OUTDIR="$(cd "${OUTDIR}" && pwd)"
INPUT_ABS="$(cd "$(dirname "${INPUT}")" && pwd)/$(basename "${INPUT}")"

STATEFILE="${OUTDIR}/.extract_v3.done"
touch "${STATEFILE}"

already_done() { grep -Fxq "$1" "${STATEFILE}"; }
mark_done()    { echo "$1" >> "${STATEFILE}"; }

lc() { echo "${1,,}"; }

is_tarish() {
  local f; f="$(lc "$1")"
  [[ "$f" == *.tar || "$f" == *.tgz || "$f" == *.tar.gz ]]
}

is_plain_gz() {
  local f; f="$(lc "$1")"
  [[ "$f" == *.gz && "$f" != *.tar.gz ]]
}

# Reject tar entries that try to escape via absolute paths or ../ traversal
validate_tar_paths() {
  local archive="$1"
  # tar -tf works for .tar, .tgz, .tar.gz on GNU tar (common on Linux)
  if ! tar -tf "$archive" >/dev/null 2>&1; then
    echo "[-] tar cannot list (maybe corrupt / not tar?): $archive" >&2
    return 1
  fi

  while IFS= read -r name; do
    [[ -z "$name" ]] && { echo "[-] Reject: empty member path in $archive" >&2; return 1; }
    [[ "$name" == /* ]] && { echo "[-] Reject: absolute path '$name' in $archive" >&2; return 1; }
    [[ "$name" == *"../"* || "$name" == "../"* || "$name" == *"..\\"* || "$name" == "..\\"* ]] && {
      echo "[-] Reject: traversal path '$name' in $archive" >&2; return 1;
    }
    [[ "$name" =~ ^[A-Za-z]:\\ ]] && { echo "[-] Reject: windows drive path '$name' in $archive" >&2; return 1; }
  done < <(tar -tf "$archive")

  return 0
}

cleanup_extracted_tree() {
  local dir="$1"
  # Remove symlinks
  find "$dir" -type l -print -delete 2>/dev/null || true
  # Remove device nodes, fifos, sockets (if any)
  find "$dir" \( -type b -o -type c -o -type p -o -type s \) -print -delete 2>/dev/null || true
}

extract_tar_safely() {
  local archive="$1"
  local dest="$2"
  mkdir -p "$dest"

  validate_tar_paths "$archive" || return 1

  # Extract (do not preserve owner/perms). GNU tar:
  tar -xf "$archive" -C "$dest" --no-same-owner --no-same-permissions

  cleanup_extracted_tree "$dest"
}

decompress_gz_safely() {
  local gz="$1"
  local dest="$2"
  mkdir -p "$dest"

  local base out
  base="$(basename "$gz")"
  base="${base%.gz}"
  out="${dest}/${base}"

  if [[ -e "$out" ]]; then
    local i=1
    while [[ -e "${out}.${i}" ]]; do ((i++)); done
    out="${out}.${i}"
  fi

  if ! gzip -cd -- "$gz" > "$out"; then
    echo "[-] gunzip failed: $gz" >&2
    rm -f "$out" 2>/dev/null || true
    return 1
  fi
}

unique_dir() {
  local d="$1"
  if [[ ! -e "$d" ]]; then
    echo "$d"
    return 0
  fi
  local i=1
  while [[ -e "${d}.${i}" ]]; do ((i++)); done
  echo "${d}.${i}"
}

echo "[*] Output: $OUTDIR"
echo "[*] Max depth: $MAX_DEPTH"
echo "[*] Top-level: $INPUT_ABS"

TOP_DIR="${OUTDIR}/top.extracted"
mkdir -p "$TOP_DIR"

# Extract/decompress top-level
if ! already_done "$INPUT_ABS"; then
  if is_tarish "$INPUT_ABS"; then
    echo "[*] Extract top tar-ish -> $TOP_DIR"
    if ! extract_tar_safely "$INPUT_ABS" "$TOP_DIR"; then
      echo "[!] Top-level extraction failed (archive rejected or unreadable): $INPUT_ABS" >&2
      exit 2
    fi
    mark_done "$INPUT_ABS"
  elif is_plain_gz "$INPUT_ABS"; then
    echo "[*] Gunzip top .gz -> $TOP_DIR"
    decompress_gz_safely "$INPUT_ABS" "$TOP_DIR" || exit 2
    mark_done "$INPUT_ABS"
  else
    echo "Error: unsupported type: $INPUT_ABS" >&2
    exit 1
  fi
fi

# Iterate passes (bounded by MAX_DEPTH but will stop early if no new work)
for ((depth=1; depth<=MAX_DEPTH; depth++)); do
  echo "[*] Pass $depth/$MAX_DEPTH: scanning for nested archives..."

  mapfile -d '' files < <(
    find "$OUTDIR" -type f \( -iname "*.tar" -o -iname "*.tgz" -o -iname "*.tar.gz" -o -iname "*.gz" \) -print0
  )

  new_work=0

  for f in "${files[@]}"; do
    f_abs="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"
    already_done "$f_abs" && continue

    parent="$(dirname "$f_abs")"
    bn="$(basename "$f_abs")"

    if is_tarish "$f_abs"; then
      dest="$(unique_dir "${parent}/${bn}.extracted")"
      echo "    [+] Extract: $f_abs"
      echo "        -> $dest"
      if extract_tar_safely "$f_abs" "$dest"; then
        mark_done "$f_abs"
        new_work=1
      else
        echo "    [!] Skipped/rejected: $f_abs" >&2
        mark_done "$f_abs" # don't retry forever
      fi

    elif is_plain_gz "$f_abs"; then
      dest="$(unique_dir "${parent}/${bn}.gunzipped")"
      echo "    [+] Gunzip: $f_abs"
      echo "        -> $dest"
      if decompress_gz_safely "$f_abs" "$dest"; then
        mark_done "$f_abs"
        new_work=1
      else
        echo "    [!] Gunzip failed: $f_abs" >&2
        mark_done "$f_abs"
      fi
    else
      mark_done "$f_abs"
    fi
  done

  if [[ "$new_work" -eq 0 ]]; then
    echo "[*] No new archives found. Done."
    break
  fi
done

echo "[*] Extraction complete."
echo "[*] Grep example:"
echo "    grep -RIn --binary-files=without-match 'KEYWORD' '$OUTDIR'"
