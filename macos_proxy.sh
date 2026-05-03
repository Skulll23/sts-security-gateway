#!/bin/bash
# ─────────────────────────────────────────────────────────
#  Toggle macOS system-wide HTTP proxy for STS
#  Usage:
#    bash ~/Desktop/sts/macos_proxy.sh --on    # route all traffic through STS
#    bash ~/Desktop/sts/macos_proxy.sh --off   # restore direct connection
# ─────────────────────────────────────────────────────────

PROXY_HOST="127.0.0.1"
PROXY_PORT="8080"

# Detect active network interface (Wi-Fi or Ethernet)
detect_interface() {
  for svc in "Wi-Fi" "Ethernet" "USB 10/100/1000 LAN" "Thunderbolt Ethernet"; do
    if networksetup -getwebproxy "$svc" &>/dev/null; then
      echo "$svc"
      return
    fi
  done
  echo ""
}

IFACE=$(detect_interface)
if [ -z "$IFACE" ]; then
  echo "❌  Could not detect a network interface. Run manually:"
  echo "    System Settings → Network → [your connection] → Details → Proxies"
  exit 1
fi

case "$1" in
  --on)
    networksetup -setwebproxy       "$IFACE" "$PROXY_HOST" "$PROXY_PORT"
    networksetup -setsecurewebproxy "$IFACE" "$PROXY_HOST" "$PROXY_PORT"
    networksetup -setwebproxystate       "$IFACE" on
    networksetup -setsecurewebproxystate "$IFACE" on
    echo "✅  System proxy ON  →  $PROXY_HOST:$PROXY_PORT  (interface: $IFACE)"
    echo "    All browser traffic now routes through STS."
    echo "    Run --off when done."
    ;;
  --off)
    networksetup -setwebproxystate       "$IFACE" off
    networksetup -setsecurewebproxystate "$IFACE" off
    echo "✅  System proxy OFF  (interface: $IFACE)"
    echo "    Browser traffic is back to direct."
    ;;
  --status)
    echo "Interface: $IFACE"
    echo "HTTP  proxy: $(networksetup -getwebproxy "$IFACE")"
    echo "HTTPS proxy: $(networksetup -getsecurewebproxy "$IFACE")"
    ;;
  *)
    echo "Usage: bash macos_proxy.sh [--on | --off | --status]"
    echo ""
    echo "  --on      Route all browser traffic through STS proxy (port 8080)"
    echo "  --off     Restore direct connection"
    echo "  --status  Show current proxy settings"
    ;;
esac
