#!/bin/bash
# ─────────────────────────────────────────────────────────
#  Semantic Traffic Sanitizer — one-shot startup script
#  Usage: bash ~/Desktop/sts/start.sh
# ─────────────────────────────────────────────────────────
set -e
STS="$HOME/Desktop/sts"
cd "$STS"

echo ""
echo "  ███████ ████████ ███████"
echo "  ██         ██    ██     "
echo "  ███████    ██    ███████"
echo "       ██    ██         ██"
echo "  ███████    ██    ███████"
echo "  Semantic Traffic Sanitizer"
echo ""

# ── Kill any previous instances ──────────────────────────
pkill -f "python3 $STS/server/app.py"    2>/dev/null && echo "Stopped old server"    || true
pkill -f "python3 $STS/dashboard/app.py" 2>/dev/null && echo "Stopped old dashboard" || true
pkill -f "mitmdump.*sts_proxy"           2>/dev/null && echo "Stopped old proxy"     || true
sleep 0.5

# ── Install dependencies if missing ──────────────────────
echo "Checking dependencies..."
pip3 install flask mitmproxy requests --quiet --break-system-packages 2>/dev/null || \
pip3 install flask mitmproxy requests --quiet

# ── Load API key ─────────────────────────────────────────
export $(grep -v '^#' "$STS/.env" | xargs)
echo "API Key loaded: ${GEMINI_API_KEY:0:10}..."

# ── Start server ─────────────────────────────────────────
echo ""
echo "Starting target server  →  http://localhost:8000"
python3 "$STS/server/app.py" > "$STS/logs/server.log" 2>&1 &
SERVER_PID=$!

# ── Start proxy ──────────────────────────────────────────
echo "Starting STS proxy      →  127.0.0.1:8080"
PATH="$HOME/.local/bin:/usr/local/bin:$PATH" mitmdump \
  -s "$STS/proxy/sts_proxy.py" \
  --listen-port 8080 \
  --ssl-insecure \
  --quiet \
  > "$STS/logs/proxy.log" 2>&1 &
PROXY_PID=$!

# ── Start dashboard ───────────────────────────────────────
echo "Starting dashboard      →  http://localhost:3000"
python3 "$STS/dashboard/app.py" > "$STS/logs/dashboard.log" 2>&1 &
DASH_PID=$!

sleep 2

# ── Health check ─────────────────────────────────────────
SERVER_OK=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/ 2>/dev/null || echo "000")
DASH_OK=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ 2>/dev/null || echo "000")

echo ""
echo "────────────────────────────────────────────────────────────"
echo "  Target server  : $([ "$SERVER_OK" = "200" ] && echo "✅ http://localhost:8000" || echo "❌ check logs/server.log")"
echo "  STS Proxy      : ✅ 127.0.0.1:8080"
echo "  Dashboard      : $([ "$DASH_OK" = "200" ] && echo "✅ http://localhost:3000" || echo "❌ check logs/dashboard.log")"
echo "────────────────────────────────────────────────────────────"
echo ""
echo "  ⚠️  macOS bypasses proxy for localhost by default."
echo "  Use the STS browser below — it forces all traffic through the proxy:"
echo ""
echo "    bash ~/Desktop/sts/open_browser.sh"
echo ""
echo "  Dashboard:  http://localhost:3000  (open this in a NORMAL browser tab)"
echo ""
echo "  Press Ctrl+C to stop all services"
echo ""

# ── Keep alive ────────────────────────────────────────────
trap "echo ''; echo 'Shutting down...'; kill $SERVER_PID $PROXY_PID $DASH_PID 2>/dev/null; exit 0" INT
wait
