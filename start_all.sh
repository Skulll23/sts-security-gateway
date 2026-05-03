#!/usr/bin/env bash
# ╔═══════════════════════════════════════════════════════════════════╗
# ║  STS — Semantic Traffic Sanitizer — One-Command Launcher          ║
# ║  Starts: VulnBank server · mitmproxy · Flask dashboard            ║
# ╚═══════════════════════════════════════════════════════════════════╝

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[STS]${RESET} $*"; }
success() { echo -e "${GREEN}[STS]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[STS]${RESET} $*"; }
err()     { echo -e "${RED}[STS] ERROR:${RESET} $*" >&2; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
cat << 'EOF'
  ███████╗████████╗███████╗
  ██╔════╝╚══██╔══╝██╔════╝
  ███████╗   ██║   ███████╗
  ╚════██║   ██║   ╚════██║
  ███████║   ██║   ███████║
  ╚══════╝   ╚═╝   ╚══════╝
  Semantic Traffic Sanitizer — UTS 41909 Capstone
EOF
echo -e "${RESET}"

# ── Load .env ─────────────────────────────────────────────────────────────────
if [[ -f ".env" ]]; then
  set -a; source .env; set +a
  success ".env loaded"
else
  warn ".env not found — AI features may not work"
fi

# ── Resolve config.json ports ────────────────────────────────────────────────
SERVER_PORT=$(python3 -c "import json; c=json.load(open('config.json')); print(c.get('server',{}).get('port',8000))" 2>/dev/null || echo 8000)
PROXY_PORT=$(python3  -c "import json; c=json.load(open('config.json')); print(c.get('proxy',{}).get('port',8080))"  2>/dev/null || echo 8080)
DASH_PORT=$(python3   -c "import json; c=json.load(open('config.json')); print(c.get('dashboard',{}).get('port',3000))" 2>/dev/null || echo 3000)
MODE=$(python3        -c "import json; c=json.load(open('config.json')); print(c.get('mode','strict'))" 2>/dev/null || echo strict)

MODE_UP=$(echo "$MODE" | tr '[:lower:]' '[:upper:]')
info "Config loaded — server:$SERVER_PORT  proxy:$PROXY_PORT  dashboard:$DASH_PORT  mode:$MODE_UP"

# ── Kill stale processes ───────────────────────────────────────────────────────
cleanup() {
  info "Shutting down STS..."
  [[ -n "${PID_SERVER:-}" ]]  && kill "$PID_SERVER"  2>/dev/null || true
  [[ -n "${PID_PROXY:-}" ]]   && kill "$PID_PROXY"   2>/dev/null || true
  [[ -n "${PID_DASH:-}" ]]    && kill "$PID_DASH"    2>/dev/null || true
  success "All services stopped."
  exit 0
}
trap cleanup SIGINT SIGTERM

pkill -f "python.*server/app" 2>/dev/null || true
pkill -f "mitmdump"           2>/dev/null || true
pkill -f "python.*dashboard"  2>/dev/null || true
sleep 0.4

# ── Prerequisites ─────────────────────────────────────────────────────────────
for cmd in python3 mitmdump; do
  if ! command -v "$cmd" &>/dev/null; then
    err "$cmd not found. Install with: pip install mitmproxy"
    exit 1
  fi
done

# Python package deps (auto-install if missing)
for pkg in flask requests fpdf2; do
  mod="${pkg//-/_}"
  if ! python3 -c "import $mod" 2>/dev/null; then
    info "Installing missing package: $pkg..."
    python3 -m pip install "$pkg" -q && success "$pkg installed" || warn "Could not install $pkg"
  fi
done

# ── Ensure dirs ───────────────────────────────────────────────────────────────
mkdir -p data logs

# ── 1. Start VulnBank target server ───────────────────────────────────────────
info "Starting VulnBank server on port $SERVER_PORT..."
python3 server/app.py > logs/server.log 2>&1 &
PID_SERVER=$!
sleep 0.8
if kill -0 "$PID_SERVER" 2>/dev/null; then
  success "VulnBank running (pid $PID_SERVER) → http://127.0.0.1:$SERVER_PORT"
else
  err "VulnBank failed to start. Check logs/server.log"
  exit 1
fi

# ── 2. Start mitmproxy addon ──────────────────────────────────────────────────
info "Starting STS proxy on port $PROXY_PORT..."
mitmdump -s proxy/sts_proxy.py --listen-port "$PROXY_PORT" \
         --set confdir="$SCRIPT_DIR/.mitmproxy" \
         > logs/proxy.log 2>&1 &
PID_PROXY=$!
sleep 1.2
if kill -0 "$PID_PROXY" 2>/dev/null; then
  success "STS Proxy running (pid $PID_PROXY) → :$PROXY_PORT"
else
  err "Proxy failed to start. Check logs/proxy.log"
  tail -20 logs/proxy.log >&2
  exit 1
fi

# ── 3. Start Flask dashboard ──────────────────────────────────────────────────
info "Starting dashboard on port $DASH_PORT..."
python3 dashboard/app.py > logs/dashboard.log 2>&1 &
PID_DASH=$!
sleep 0.8
if kill -0 "$PID_DASH" 2>/dev/null; then
  success "Dashboard running (pid $PID_DASH) → http://127.0.0.1:$DASH_PORT"
else
  err "Dashboard failed to start. Check logs/dashboard.log"
  tail -20 logs/dashboard.log >&2
  exit 1
fi

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${GREEN}✓${RESET} VulnBank target   ${BOLD}http://127.0.0.1:$SERVER_PORT${RESET}"
echo -e "  ${GREEN}✓${RESET} STS Proxy          ${BOLD}127.0.0.1:$PROXY_PORT${RESET}  (HTTP)"
echo -e "  ${GREEN}✓${RESET} SOC Dashboard      ${BOLD}http://127.0.0.1:$DASH_PORT${RESET}"
echo -e "  ${CYAN}⚙${RESET} Mode               ${BOLD}${MODE_UP}${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${YELLOW}→ Open browser via proxy:${RESET}"
echo -e "    bash open_browser.sh"
echo ""
echo -e "  ${YELLOW}→ Fire a test attack (in another terminal):${RESET}"
echo -e "    curl -x http://127.0.0.1:$PROXY_PORT 'http://127.0.0.1:$SERVER_PORT/search?q=%27+OR+1%3D1--'"
echo ""
echo -e "  ${YELLOW}→ Change mode live:${RESET} click the mode badge on the dashboard"
echo ""
echo -e "  ${RED}Press Ctrl+C to stop all services${RESET}"
echo ""

# ── Wait (keep script alive so Ctrl+C triggers cleanup) ──────────────────────
wait
