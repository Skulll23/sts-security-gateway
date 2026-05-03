#!/bin/bash
# ─────────────────────────────────────────────────────────
#  Opens a Chrome window with mitmproxy forced on localhost.
#
#  macOS normally bypasses the system proxy for localhost —
#  this script overrides that using Chrome's --proxy-server
#  and --proxy-bypass-list="<-loopback>" flags.
#
#  Usage: bash ~/Desktop/sts/open_browser.sh
# ─────────────────────────────────────────────────────────

PROXY="http://127.0.0.1:8080"
TARGET="http://localhost:8000"

# Find Chrome (handles different install locations)
CHROME=""
for path in \
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  "/Applications/Chromium.app/Contents/MacOS/Chromium" \
  "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"; do
  if [ -f "$path" ]; then
    CHROME="$path"
    break
  fi
done

if [ -z "$CHROME" ]; then
  echo "❌  Chrome not found."
  echo "    Install Google Chrome, or manually set proxy to 127.0.0.1:8080 in your browser."
  echo "    In Chrome: Settings → System → Open proxy settings"
  exit 1
fi

echo "🚀  Opening STS test browser..."
echo "    Proxy : $PROXY (localhost bypass disabled)"
echo "    Target: $TARGET"
echo ""
echo "    ➡  Open http://localhost:3000 in a SEPARATE normal browser tab for the dashboard."
echo ""

# --proxy-bypass-list="<-loopback>" tells Chrome NOT to skip the proxy for localhost
"$CHROME" \
  --proxy-server="$PROXY" \
  --proxy-bypass-list="<-loopback>" \
  --user-data-dir="/tmp/sts-chrome-profile" \
  "$TARGET" \
  2>/dev/null &

echo "✅  Browser opened. All traffic (including localhost) now routes through STS."
