#!/usr/bin/env bash
# C3 - Continuous CVE Coverage - setup script.
#
# Detects environment, copies example configs if missing, builds the docker
# image, and validates everything. Hard-stops with an actionable error if
# the environment is wrong.
#
# Usage:
#   ./setup.sh                # auto-detect (prefers docker)
#   ./setup.sh --docker       # force docker path
#   ./setup.sh --local        # force local-python path (pip install, venv)
#   ./setup.sh --help         # show help
#   ./setup.sh --skip-build   # only copy configs and validate, skip image build

set -euo pipefail

# ---------- styling ----------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; RED=$'\033[31m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=''; DIM=''; GREEN=''; YELLOW=''; RED=''; CYAN=''; RESET=''
fi

msg()  { printf "%s\n" "${CYAN}>>${RESET} $1"; }
ok()   { printf "%s\n" "${GREEN}OK${RESET} $1"; }
warn() { printf "%s\n" "${YELLOW}!!${RESET} $1"; }
die()  { printf "%s\n" "${RED}ERROR${RESET} $1" >&2; exit 1; }

# ---------- usage ----------
usage() {
    cat <<EOF
${BOLD}C3 setup${RESET} - get a working ccc deployment in one command.

${BOLD}Usage:${RESET}
    ./setup.sh [OPTIONS]

${BOLD}Options:${RESET}
    --docker       force docker mode (default when docker is available)
    --local        force local-python mode (creates .venv, hash-pinned install)
    --skip-build   copy configs + validate but do not build / install
    --help, -h     show this message

${BOLD}What it does:${RESET}
    1. Picks docker mode (recommended) or local mode (--local).
    2. Copies config/*.example.yaml -> config/*.yaml if missing.
    3. Docker mode: builds ccc:local image with hash-pinned deps.
       Local mode:  creates .venv, pip install --require-hashes from lockfile.
    4. Validates your config and resolves product names to CPEs.

${BOLD}After setup:${RESET}
    - Edit config/config.yaml (add Google Chat webhook URL + optional NVD key)
    - Edit config/products.yaml (list product names)
    - Run:  docker compose run --rm ccc run     (docker mode)
    - or:   .venv/bin/ccc run                   (local mode)
EOF
}

# ---------- arg parse ----------
MODE="auto"
SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --docker)     MODE="docker" ;;
        --local)      MODE="local" ;;
        --skip-build) SKIP_BUILD=true ;;
        --help|-h)    usage; exit 0 ;;
        *)            warn "unknown option: $arg"; usage; exit 2 ;;
    esac
done

# ---------- repo root check ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

[ -f docker-compose.yml ] || die "docker-compose.yml not found. Run setup.sh from the ccc repo root."
[ -f Dockerfile ] || die "Dockerfile not found. Run setup.sh from the ccc repo root."

# ---------- sudo / root warning ----------
# ccc is not meant to run as root. setup.sh under sudo creates .venv, state/,
# and config/*.yaml owned by root - the operator's normal-user cron then
# cannot write state. Bail out loud so the operator notices.
if [ "$(id -u 2>/dev/null || echo 0)" -eq 0 ]; then
    warn "setup.sh is running as root."
    warn "This will create .venv/, state/, and config/*.yaml owned by root,"
    warn "which breaks subsequent non-root cron runs."
    warn "Run setup.sh WITHOUT sudo. ccc itself never needs root."
    warn ""
    warn "If you really know what you're doing, set CCC_ALLOW_ROOT=1 to skip."
    if [ "${CCC_ALLOW_ROOT:-}" != "1" ]; then
        die "refusing to continue as root. Re-run without sudo."
    fi
    warn "CCC_ALLOW_ROOT=1 set, continuing under root."
fi

# ---------- step 1: environment detection / mode resolution ----------
msg "Detecting environment ..."

DOCKER_AVAILABLE=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    DOCKER_AVAILABLE=true
    ok "docker found ($(docker --version | awk '{print $3}' | tr -d ','))"
fi

PYTHON_AVAILABLE=false
PYTHON_BIN=""
for cand in python3.13 python3.12 python3.11 python3; do
    if command -v "$cand" >/dev/null 2>&1; then
        pyver=$("$cand" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null || echo "")
        # Require >= 3.11
        major=${pyver%%.*}
        minor=${pyver##*.}
        if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ] 2>/dev/null; then
            PYTHON_AVAILABLE=true
            PYTHON_BIN="$cand"
            ok "python found ($cand, version $pyver)"
            break
        fi
    fi
done

# Resolve mode
if [ "$MODE" = "auto" ]; then
    if [ "$DOCKER_AVAILABLE" = true ]; then
        MODE="docker"
    elif [ "$PYTHON_AVAILABLE" = true ]; then
        MODE="local"
        warn "docker unavailable; falling back to local-python mode"
    else
        die "Neither docker nor python >=3.11 found. Install docker: https://docs.docker.com/get-docker/"
    fi
fi

if [ "$MODE" = "docker" ] && [ "$DOCKER_AVAILABLE" = false ]; then
    die "Docker mode requested but docker is unavailable (not installed or daemon not running)."
fi

if [ "$MODE" = "local" ] && [ "$PYTHON_AVAILABLE" = false ]; then
    die "Local mode requested but python >= 3.11 not found on PATH."
fi

msg "Using ${BOLD}$MODE${RESET} mode"

# ---------- step 2: docker compose check (docker mode only) ----------
if [ "$MODE" = "docker" ]; then
    if ! docker compose version >/dev/null 2>&1; then
        die "docker compose plugin not installed. See: https://docs.docker.com/compose/install/"
    fi
    ok "docker compose available"
fi

# ---------- step 3: copy example configs ----------
msg "Setting up config files ..."

mkdir -p config

if [ ! -f config/config.yaml ]; then
    cp config/config.example.yaml config/config.yaml
    ok "created config/config.yaml from example"

    # Local mode needs host paths, not the docker bind-mount paths.
    # Rewrite state_dir + products_file so ccc finds them on the host.
    # Done via python to safely handle paths with #, &, spaces, quotes etc.
    # sed delimiter collisions silently corrupted config.yaml in earlier versions.
    if [ "$MODE" = "local" ]; then
        local_state_dir="$SCRIPT_DIR/state"
        local_products="$SCRIPT_DIR/config/products.yaml"
        mkdir -p "$local_state_dir"

        rewrite_status=0
        STATE_DIR="$local_state_dir" PRODUCTS_FILE="$local_products" \
        "${PYTHON_BIN:-python3}" - <<'PY' || rewrite_status=$?
import os
import sys
from pathlib import Path

state_dir = os.environ["STATE_DIR"]
products_file = os.environ["PRODUCTS_FILE"]
cfg = Path("config/config.yaml")
try:
    lines = cfg.read_text(encoding="utf-8").splitlines(keepends=True)
except OSError as e:
    print(f"could not read config/config.yaml: {e}", file=sys.stderr)
    sys.exit(2)

out = []
seen_state = seen_products = False
for line in lines:
    stripped = line.lstrip()
    if stripped.startswith("state_dir:"):
        # Quote the value so YAML cannot misparse special chars in paths.
        out.append(f'state_dir: "{state_dir}"\n')
        seen_state = True
    elif stripped.startswith("products_file:"):
        out.append(f'products_file: "{products_file}"\n')
        seen_products = True
    else:
        out.append(line)

if not seen_state:
    out.append(f'state_dir: "{state_dir}"\n')
if not seen_products:
    out.append(f'products_file: "{products_file}"\n')

try:
    cfg.write_text("".join(out), encoding="utf-8")
except OSError as e:
    print(f"could not write config/config.yaml: {e}", file=sys.stderr)
    sys.exit(2)
PY
        if [ "$rewrite_status" -ne 0 ]; then
            die "failed to rewrite config/config.yaml for local mode (exit $rewrite_status)"
        fi
        ok "rewrote state_dir + products_file for local mode"
    fi

    warn "you MUST edit config/config.yaml before running ccc:"
    warn "  - set google_chat_webhook to your Chat space's Incoming Webhook URL"
    warn "  - optionally set nvd_api_key (faster + higher rate limit)"
else
    ok "config/config.yaml already exists (not overwriting)"
fi

if [ ! -f config/products.yaml ]; then
    cp config/products.example.yaml config/products.yaml
    ok "created config/products.yaml from example"
    warn "edit config/products.yaml to list the products you want monitored"
else
    ok "config/products.yaml already exists (not overwriting)"
fi

# ---------- step 4: build / install ----------
if [ "$SKIP_BUILD" = true ]; then
    warn "skipping build (--skip-build)"
elif [ "$MODE" = "docker" ]; then
    msg "Building ccc:local image (hash-pinned deps) ..."
    if ! docker compose build ccc 2>&1 | tail -20; then
        die "image build failed. See output above."
    fi
    ok "image ccc:local built"
else
    msg "Creating .venv and installing hash-pinned deps ..."
    if [ ! -d .venv ]; then
        "$PYTHON_BIN" -m venv .venv || die "failed to create venv"
        ok ".venv created"
    else
        ok ".venv already exists (reusing)"
    fi
    .venv/bin/pip install --quiet --upgrade pip >/dev/null
    if ! .venv/bin/pip install --require-hashes --no-deps -r requirements.lock; then
        die "pip install failed. Lockfile or network issue."
    fi
    if ! .venv/bin/pip install --quiet --no-deps -e .; then
        die "ccc editable install failed."
    fi
    ok "ccc installed in .venv (run via .venv/bin/ccc)"
fi

# ---------- step 5: validate ----------
msg "Validating config + resolving product CPEs ..."

if [ "$MODE" = "docker" ]; then
    set +e
    docker compose run --rm ccc validate
    rc=$?
    set -e
else
    set +e
    # Local mode: ccc expects state_dir + products_file from config.yaml.
    # The example config uses /state and /config paths intended for the
    # docker bind-mounts. For local mode we override via env-aware paths.
    CCC_CONFIG="$SCRIPT_DIR/config/config.yaml" .venv/bin/ccc validate
    rc=$?
    set -e
fi

if [ "$rc" -eq 0 ]; then
    ok "validation passed"
elif [ "$rc" -eq 1 ]; then
    warn "validation found problems - fix them in config/config.yaml or config/products.yaml and re-run:"
    if [ "$MODE" = "docker" ]; then
        warn "    docker compose run --rm ccc validate"
    else
        warn "    .venv/bin/ccc validate"
    fi
    exit 1
else
    die "validate exited with code $rc"
fi

# ---------- step 6: next steps ----------
if [ "$MODE" = "docker" ]; then
    RUN_CMD="docker compose run --rm ccc"
else
    RUN_CMD=".venv/bin/ccc"
fi

cat <<EOF

${GREEN}${BOLD}Setup complete.${RESET}  (mode: $MODE)

${BOLD}Next steps:${RESET}

  ${DIM}# Edit config/config.yaml - set google_chat_webhook to your real URL${RESET}
  \$EDITOR config/config.yaml

  ${DIM}# Edit config/products.yaml - list products you care about${RESET}
  \$EDITOR config/products.yaml

  ${DIM}# Send a test message to your Chat space${RESET}
  $RUN_CMD test-webhook

  ${DIM}# Live run (one poll cycle)${RESET}
  $RUN_CMD run

  ${DIM}# Schedule it hourly via systemd${RESET}
  sudo cp systemd/ccc.service systemd/ccc.timer /etc/systemd/system/
  sudo sed -i "s|/opt/ccc|\$(pwd)|" /etc/systemd/system/ccc.service
  sudo systemctl daemon-reload
  sudo systemctl enable --now ccc.timer

See README.md for the full architecture and configuration reference.
EOF
