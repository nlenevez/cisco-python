#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Usage:
#   ./safe_recursive_extract.sh input.tgz /path/to/output [max_depth]
#
# Notes:
# - Handles .tar, .tgz, .tar.gz, and .gz (plain gzip -> decompressed file)
# - Nested up to max_depth (default 8)
# - For untrusted archives: validates tar member paths BEFORE extraction
# - Skips symlinks/hardlinks/devices for safety

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

STATEFILE="${OUTDIR}/.safe_recursive_extract.done"
touch "${STATEFILE}"

already_done() { grep -Fxq "$1" "${STATEFILE}"; }
mark_done()    { echo "$1" >> "${STATEFILE}"; }

folder_from_archive() {
  local f
  f="$(basename "$1")"
  f="${f%.tar.gz}"
  f="${f%.tgz}"
  f="${f%.tar}"
  f="${f%.gz}"
  echo "${f}"
}

is_tarish() {
  local f="$1"
  shopt -s nocasematch
  [[ "$f" == *.tar || "$f" == *.tgz || "$f" == *.tar.gz ]]
}

is_gz() {
  local f="$1"
  shopt -s nocasematch
  [[ "$f" == *.gz && "$f" != *.tar.gz ]]
}

# Validate tar member paths (block traversal / absolute / weirdness)
validate_tar_paths() {
  local archive="$1"

  # list member names only
  # -t: list, -f: file
  # For .tgz/.tar.gz, tar auto-detects with -z? Not always. Use tar -tf; GNU tar detects via suffix in many distros,
  # but to be robust we use gzip -cd | tar -tf - for gzipped ones.
  local list_cmd

  if [[ "${archive,,}" == *.tgz || "${archive,,}" == *.tar.gz ]]; then
    # list via gzip stream to be consistent across tars
    list_cmd=(bash -c 'gzip -cd -- "$1" | tar -tf -' _ "${archive}")
  else
    list_cmd=(tar -tf "${archive}")
  fi

  # Read each member and check for dangerous paths
  # Reject:
  #  - absolute paths (/...)
  #  - parent traversal (../ or ..\)
  #  - Windows drive paths (C:\)
  #  - empty names
  #  - paths with NUL (shouldn't happen in shell anyway)
  while IFS= read -r name; do
    [[ -z "${name}" ]] && { echo "[-] Reject: empty path in ${archive}"; return 1; }

    # Normalize some obvious bad patterns
    if [[ "${name}" == /* ]]; then
      echo "[-] Reject: absolute path '${name}' in ${archive}"
      return 1
    fi
    if [[ "${name}" == *"../"* || "${name}" == "../"* || "${name}" == *"..\\"* || "${name}" == "..\\"* ]]; then
      echo "[-] Reject: traversal path '${name}' in ${archive}"
      return 1
    fi
    if [[ "${name}" =~ ^[A-Za-z]:\\ ]]; then
      echo "[-] Reject: windows drive path '${name}' in ${archive}"
      return 1
    fi
  done < <("${list_cmd[@]}")

  return 0
}

# Extract tar safely, skipping symlinks/hardlinks/devices
extract_tar_safely() {
  local archive="$1"
  local dest="$2"

  mkdir -p "${dest}"

  # First: validate member paths
  validate_tar_paths "${archive}"

  # Now extract, but exclude risky entry types (symlinks, hardlinks, devices, fifos)
  # We do this by using tar -tvf to identify types, then re-extract only "regular files" and "directories".
  # tar -tvf output first char:
  #   - regular file, d directory, l symlink, h hard link, c char dev, b block dev, p fifo, s socket (rare)
  local extract_stream
  if [[ "${archive,,}" == *.tgz || "${archive,,}" == *.tar.gz ]]; then
    extract_stream=(bash -c 'gzip -cd -- "$1" | tar -tvf -' _ "${archive}")
  else
    extract_stream=(tar -tvf "${archive}")
  fi

  mapfile -t safe_paths < <(
    "${extract_stream[@]}" | awk '
      {
        t=substr($1,1,1);
        # keep regular files and dirs only
        if (t=="-" || t=="d") {
          # name is from field 6 onward (spaces possible), so rebuild
          name="";
          for (i=6;i<=NF;i++) { name = name (i==6?"":" ") $i }
          print name
        }
      }'
  )

  if [[ "${#safe_paths[@]}" -eq 0 ]]; then
    echo "[-] Nothing safe to extract from ${archive} (only links/devices?)"
    return 0
  fi

  if [[ "${archive,,}" == *.tgz || "${archive,,}" == *.tar.gz ]]; then
    gzip -cd -- "${archive}" | tar -xvf - \
      -C "${dest}" \
      --no-same-owner --no-same-permissions \
      --warning=no-unknown-keyword \
      "${safe_paths[@]}" >/dev/null
  else
    tar -xvf "${archive}" \
      -C "${dest}" \
      --no-same-owner --no-same-permissions \
      --warning=no-unknown-keyword \
      "${safe_paths[@]}" >/dev/null
  fi
}

# Decompress a plain .gz to a sibling file in a controlled folder
decompress_gz_safely() {
  local gz="$1"
  local destdir="$2"

  mkdir -p "${destdir}"
  local out_name
  out_name="$(basename "${gz}")"
  out_name="${out_name%.gz}"
  local out_path="${destdir}/${out_name}"

  # Avoid overwrite
  if [[ -e "${out_path}" ]]; then
    local i=1
    while [[ -e "${out_path}.${i}" ]]; do ((i++)); done
    out_path="${out_path}.${i}"
  fi

  # -c to stdout, redirect into file
  gzip -cd -- "${gz}" > "${out_path}"
}

echo "[*] Output: ${OUTDIR}"
echo "[*] Max depth: ${MAX_DEPTH}"

# Put top-level into its own folder under OUTDIR
TOP_FOLDER="${OUTDIR}/$(folder_from_archive "${INPUT_ABS}")"
mkdir -p "${TOP_FOLDER}"

# Process the top-level input
if ! already_done "${INPUT_ABS}"; then
  if is_tarish "${INPUT_ABS}"; then
    echo "[*] Extract top-level tar: ${INPUT_ABS}"
    extract_tar_safely "${INPUT_ABS}" "${TOP_FOLDER}"
    mark_done "${INPUT_ABS}"
  elif is_gz "${INPUT_ABS}"; then
    echo "[*] Decompress top-level gz: ${INPUT_ABS}"
    decompress_gz_safely "${INPUT_ABS}" "${TOP_FOLDER}"
    mark_done "${INPUT_ABS}"
  else
    echo "Error: unsupported input type (expected .tar/.tgz/.tar.gz/.gz): ${INPUT_ABS}"
    exit 1
  fi
fi

# Iterate nested extractions
for ((depth=1; depth<=MAX_DEPTH; depth++)); do
  echo "[*] Scan depth ${depth}/${MAX_DEPTH}..."

  mapfile -d '' candidates < <(
    find "${OUTDIR}" -type f \( \
      -iname "*.tar" -o -iname "*.tgz" -o -iname "*.tar.gz" -o \
      \( -iname "*.gz" -a ! -iname "*.tar.gz" \) \
    \) -print0
  )

  new_work=0

  for f in "${candidates[@]}"; do
    f_abs="$(cd "$(dirname "${f}")" && pwd)/$(basename "${f}")"
    already_done "${f_abs}" && continue

    parent="$(dirname "${f_abs}")"
    base="$(folder_from_archive "${f_abs}")"
    dest="${parent}/${base}.extracted"

    # unique dest
    if [[ -e "${dest}" ]]; then
      i=1
      while [[ -e "${dest}.${i}" ]]; do ((i++)); done
      dest="${dest}.${i}"
    fi

    if is_tarish "${f_abs}"; then
      echo "    [+] Extract tar: ${f_abs}"
      echo "        -> ${dest}"
      if extract_tar_safely "${f_abs}" "${dest}"; then
        mark_done "${f_abs}"
        new_work=1
      else
        echo "    [!] Skipped suspicious archive: ${f_abs}"
        mark_done "${f_abs}"   # mark so we don't keep retrying it
      fi
    elif is_gz "${f_abs}"; then
      echo "    [+] Decompress gz: ${f_abs}"
      echo "        -> ${dest}"
      decompress_gz_safely "${f_abs}" "${dest}"
      mark_done "${f_abs}"
      new_work=1
    fi
  done

  if [[ "${new_work}" -eq 0 ]]; then
    echo "[*] No new archives found. Done."
    break
  fi
done

echo "[*] Finished."
echo "[*] Grep example:"
echo "    grep -RIn --binary-files=without-match 'KEYWORD' '${OUTDIR}'"
