#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Usage:
#   ./safe_recursive_extract_v2.sh input.tar.gz output_dir [max_depth]
#
# Handles:
#   .tar, .tgz, .tar.gz, and plain .gz (NOT .zip etc)
# Security (untrusted):
#   - Reject tar members with absolute paths or ../ traversal
#   - Extract only regular files + directories (skip symlinks/hardlinks/devices/fifos)
#   - Never preserve ownership/perms
# Behavior:
#   - Each archive extracts into "<archive>.extracted" folder next to it
#   - Plain .gz is decompressed into "<name>.gunzipped" folder next to it

INPUT="${1:-}"
OUTDIR="${2:-}"
MAX_DEPTH="${3:-8}"

if [[ -z "${INPUT}" || -z "${OUTDIR}" ]]; then
  echo "Usage: $0 <input.tar|.tgz|.tar.gz|.gz> <output_dir> [max_depth]"
  exit 1
fi
if [[ ! -f "${INPUT}" ]]; then
  echo "Error: input file not found: ${INPUT}"
  exit 1
fi

mkdir -p "${OUTDIR}"
OUTDIR="$(cd "${OUTDIR}" && pwd)"
INPUT_ABS="$(cd "$(dirname "${INPUT}")" && pwd)/$(basename "${INPUT}")"

STATEFILE="${OUTDIR}/.extract_v2.done"
touch "${STATEFILE}"

already_done() { grep -Fxq "$1" "${STATEFILE}"; }
mark_done()    { echo "$1" >> "${STATEFILE}"; }

lower_ext() { echo "${1,,}"; }

is_tarish() {
  local f; f="$(lower_ext "$1")"
  [[ "$f" == *.tar || "$f" == *.tgz || "$f" == *.tar.gz ]]
}

is_plain_gz() {
  local f; f="$(lower_ext "$1")"
  [[ "$f" == *.gz && "$f" != *.tar.gz ]]
}

# List tar members (names only), robust for gzipped tars too
tar_list_names() {
  local archive="$1"
  local a; a="$(lower_ext "$archive")"
  if [[ "$a" == *.tgz || "$a" == *.tar.gz ]]; then
    gzip -cd -- "$archive" | tar -tf -
  else
    tar -tf "$archive"
  fi
}

# Validate tar paths against traversal/absolute/drive-letter
validate_tar_paths() {
  local archive="$1"
  while IFS= read -r name; do
    [[ -z "$name" ]] && { echo "[-] Reject: empty member path in $archive"; return 1; }
    [[ "$name" == /* ]] && { echo "[-] Reject: absolute path '$name' in $archive"; return 1; }
    [[ "$name" == *"../"* || "$name" == "../"* || "$name" == *"..\\"* || "$name" == "..\\"* ]] && {
      echo "[-] Reject: traversal path '$name' in $archive"; return 1;
    }
    [[ "$name" =~ ^[A-Za-z]:\\ ]] && { echo "[-] Reject: windows drive path '$name' in $archive"; return 1; }
  done < <(tar_list_names "$archive")
}

# Extract only regular files and directories (skip links/devices/fifos)
extract_tar_safely() {
  local archive="$1"
  local dest="$2"
  mkdir -p "$dest"

  validate_tar_paths "$archive"

  # Get verbose listing so we can filter types.
  # GNU tar -tvf format can vary; we use the first char of mode field.
  local a; a="$(lower_ext "$archive")"
  local listing
  if [[ "$a" == *.tgz || "$a" == *.tar.gz ]]; then
    listing="$(gzip -cd -- "$archive" | tar -tvf -)"
  else
    listing="$(tar -tvf "$archive")"
  fi

  # Extract names for regular files/dirs only.
  # We parse from the end by removing the first 5 fields (mode, user/group, size, date, time/year),
  # then keeping the rest as the filename. This works for GNU tar typical output.
  mapfile -t safe_paths < <(
    printf '%s\n' "$listing" | awk '
      {
        t=substr($1,1,1);
        if (t=="-" || t=="d") {
          name="";
          for (i=6;i<=NF;i++) name = name (i==6?"":" ") $i;
          print name
        }
      }'
  )

  if [[ "${#safe_paths[@]}" -eq 0 ]]; then
    echo "[-] Nothing safe to extract from $archive"
    return 0
  fi

  if [[ "$a" == *.tgz || "$a" == *.tar.gz ]]; then
    gzip -cd -- "$archive" | tar -xvf - \
      -C "$dest" \
      --no-same-owner --no-same-permissions \
      --warning=no-unknown-keyword \
      "${safe_paths[@]}" >/dev/null
  else
    tar -xvf "$archive" \
      -C "$dest" \
      --no-same-owner --no-same-permissions \
      --warning=no-unknown-keyword \
      "${safe_paths[@]}" >/dev/null
  fi
}

decompress_gz_safely() {
  local gz="$1"
  local dest="$2"
  mkdir -p "$dest"

  local base out
  base="$(basename "$gz")"
  base="${base%.gz}"
  out="${dest}/${base}"

  # avoid overwrite
  if [[ -e "$out" ]]; then
    local i=1
    while [[ -e "${out}.${i}" ]]; do ((i++)); done
    out="${out}.${i}"
  fi

  gzip -cd -- "$gz" > "$out"
}

echo "[*] Output: $OUTDIR"
echo "[*] Max depth: $MAX_DEPTH"
echo "[*] Top-level: $INPUT_ABS"

# Put the initial input into its own folder
TOP_DIR="${OUTDIR}/top.extracted"
mkdir -p "$TOP_DIR"

if ! already_done "$INPUT_ABS"; then
  if is_tarish "$INPUT_ABS"; then
    echo "[*] Extract top tar-ish -> $TOP_DIR"
    extract_tar_safely "$INPUT_ABS" "$TOP_DIR"
    mark_done "$INPUT_ABS"
  elif is_plain_gz "$INPUT_ABS"; then
    echo "[*] Decompress top gz -> $TOP_DIR"
    decompress_gz_safely "$INPUT_ABS" "$TOP_DIR"
    mark_done "$INPUT_ABS"
  else
    echo "Error: unsupported type: $INPUT_ABS"
    exit 1
  fi
fi

# Queue-based expansion by depth
for ((depth=1; depth<=MAX_DEPTH; depth++)); do
  echo "[*] Pass $depth/$MAX_DEPTH: scanning for .tar/.tgz/.tar.gz/.gz ..."

  # Robust extension match (case-insensitive) via -iregex
  mapfile -d '' files < <(
    find "$OUTDIR" -type f \
      -iregex '.*\.\(tar\|tgz\|tar\.gz\|gz\)$' -print0
  )

  new_work=0

  for f in "${files[@]}"; do
    f_abs="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")"
    already_done "$f_abs" && continue

    parent="$(dirname "$f_abs")"
    bn="$(basename "$f_abs")"

    if is_tarish "$f_abs"; then
      dest="${parent}/${bn}.extracted"
      # unique folder
      if [[ -e "$dest" ]]; then
        i=1; while [[ -e "${dest}.${i}" ]]; do ((i++)); done
        dest="${dest}.${i}"
      fi

      echo "    [+] Extract: $f_abs"
      echo "        -> $dest"
      if extract_tar_safely "$f_abs" "$dest"; then
        mark_done "$f_abs"
        new_work=1
      else
        echo "    [!] Skipped suspicious tar: $f_abs"
        mark_done "$f_abs"
      fi

    elif is_plain_gz "$f_abs"; then
      dest="${parent}/${bn}.gunzipped"
      if [[ -e "$dest" ]]; then
        i=1; while [[ -e "${dest}.${i}" ]]; do ((i++)); done
        dest="${dest}.${i}"
      fi

      echo "    [+] Gunzip: $f_abs"
      echo "        -> $dest"
      decompress_gz_safely "$f_abs" "$dest"
      mark_done "$f_abs"
      new_work=1
    else
      # Shouldn't happen due to regex, but just in case:
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
