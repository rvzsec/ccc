#!/usr/bin/env bash
# C³ dependency audit.
#
# Downloads every pinned wheel/sdist from PyPI and prints its SHA256 alongside
# the hash declared in requirements.lock. Run BEFORE trusting the lockfile in a
# new environment, especially after a deliberate version bump.
#
# Verdict logic:
#   match    -> wheel SHA256 matches one of the lockfile hashes
#   MISMATCH -> bail. Either lockfile is wrong or PyPI is serving something else.
#
# Usage (host):
#   docker compose run --rm audit
#
# This container has zero project dependencies - it only uses pip's download
# subcommand against a known-good Python base image.

set -euo pipefail
shopt -s nullglob nocaseglob

LOCK=/audit/requirements.lock
WORKDIR=/tmp/ccc-audit
mkdir -p "$WORKDIR"

echo "=========================================================="
echo "C3 dependency audit"
echo "lockfile: $LOCK"
echo "workdir:  $WORKDIR"
echo "=========================================================="

# Extract `pkg==ver` lines (ignore comments + hash continuations).
mapfile -t PKGS < <(grep -E '^[a-zA-Z0-9_.\-]+==[0-9]' "$LOCK" | awk '{print $1}')

if [ "${#PKGS[@]}" -eq 0 ]; then
  echo "ERROR: no packages found in lockfile" >&2
  exit 1
fi

echo
echo "Will audit ${#PKGS[@]} pinned packages:"
printf '  - %s\n' "${PKGS[@]}"
echo

FAIL=0
PASS=0
for spec in "${PKGS[@]}"; do
  echo "----------------------------------------------------------"
  echo "Auditing: $spec"
  pkg_name="${spec%%==*}"
  pkg_ver="${spec##*==}"

  # Match the same wheel platform/python as the runtime image so we audit
  # exactly the bytes the runtime will install.
  pip download "$spec" \
      --no-deps \
      --dest "$WORKDIR" \
      --only-binary=:all: \
      --platform manylinux2014_x86_64 \
      --python-version 3.13 \
      --quiet \
      --disable-pip-version-check 2>&1 | sed 's/^/  pip: /' || {
        # Fall back to any wheel format (pure-python packages without platform).
        pip download "$spec" \
            --no-deps \
            --dest "$WORKDIR" \
            --only-binary=:all: \
            --quiet \
            --disable-pip-version-check 2>&1 | sed 's/^/  pip: /'
      }

  # Collect candidate files. PyPI normalizes dashes <-> underscores in wheel
  # filenames, so try both. Then dedup so we hash each artifact once.
  pkg_name_under="${pkg_name//-/_}"
  pkg_name_dash="${pkg_name//_/-}"

  candidates=(
    "$WORKDIR"/"${pkg_name_under}"-"${pkg_ver}"-*.whl
    "$WORKDIR"/"${pkg_name_dash}"-"${pkg_ver}"-*.whl
    "$WORKDIR"/"${pkg_name_under}"-"${pkg_ver}".tar.gz
    "$WORKDIR"/"${pkg_name_dash}"-"${pkg_ver}".tar.gz
  )

  # Dedup by inode-stable absolute path.
  declare -A seen=()
  files=()
  for c in "${candidates[@]}"; do
    [ -e "$c" ] || continue
    real=$(readlink -f -- "$c")
    if [ -z "${seen[$real]+x}" ]; then
      seen[$real]=1
      files+=("$real")
    fi
  done

  if [ "${#files[@]}" -eq 0 ]; then
    echo "  ! no artifact downloaded for $spec"
    FAIL=$((FAIL + 1))
    continue
  fi

  for f in "${files[@]}"; do
    actual=$(sha256sum "$f" | awk '{print $1}')
    if grep -qF "$actual" "$LOCK"; then
      echo "  OK $(basename "$f")"
      echo "     sha256 = $actual  (matches lockfile)"
      PASS=$((PASS + 1))
    else
      echo "  FAIL $(basename "$f")"
      echo "       sha256 = $actual"
      echo "       NOT in lockfile - check https://pypi.org/project/${pkg_name}/${pkg_ver}/#files"
      FAIL=$((FAIL + 1))
    fi
  done

  unset seen
done

echo
echo "=========================================================="
echo "Summary: $PASS match, $FAIL fail"
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: $FAIL artifact(s) did not match the lockfile."
  echo "Do NOT trust this lockfile until you investigate."
  exit 1
fi
echo "OK: every pinned artifact hash matches the lockfile."
echo "=========================================================="
