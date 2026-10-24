#!/usr/bin/env bash
# Install the SENTRIX bot on a fresh Ubuntu or Debian server. Run as root:
#   curl -fsSL https://raw.githubusercontent.com/longsengchhun-crypto/Master_Tool/main/deploy/install.sh | sudo bash
# It installs Docker, asks for the bot token (typed hidden, stored only in /opt/sentrix/.env, readable by root only),
# and starts the bot. It restarts by itself after a crash or a reboot and updates itself when a new version is published.
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/longsengchhun-crypto/Master_Tool/main/deploy"
DIR=/opt/sentrix

[ "$(id -u)" = 0 ] || { echo "Run this as root (sudo)." >&2; exit 1; }

if ! command -v docker >/dev/null 2>&1; then
  echo "==> Installing Docker"
  curl -fsSL https://get.docker.com | sh
fi

mkdir -p "$DIR"
cd "$DIR"
for f in docker-compose.yml Caddyfile; do curl -fsSL "$REPO_RAW/$f" -o "$f"; done

if [ ! -s .env ]; then
  TOKEN="${SENTRIX_BOT_TOKEN:-}"
  if [ -z "$TOKEN" ]; then
    read -r -s -p "Bot token from @BotFather (typing is hidden): " TOKEN < /dev/tty
    echo
  fi
  [ -n "$TOKEN" ] || { echo "No token given." >&2; exit 1; }
  read -r -p "Your own domain name pointing at this server (press Enter to use a free automatic address): " DOMAIN < /dev/tty || DOMAIN=""
  if [ -z "$DOMAIN" ]; then
    # No domain bought: sslip.io turns the server's public IP into a real hostname, and Caddy gets a real HTTPS certificate for it.
    IP="$(curl -fsS4 https://api.ipify.org || curl -fsS4 https://ifconfig.me)"
    DOMAIN="$(echo "$IP" | tr . -).sslip.io"
  fi
  umask 077
  printf 'SENTRIX_BOT_TOKEN=%s\nDOMAIN=%s\n' "$TOKEN" "$DOMAIN" > .env
  chmod 600 .env
  unset TOKEN
fi

# The app reaches the bot through this HTTPS address, so it is always set up.
PROFILE="--profile https"
DOMAIN="$(grep '^DOMAIN=' .env | cut -d= -f2-)"
if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp >/dev/null 2>&1 || true; ufw allow 443/tcp >/dev/null 2>&1 || true; fi

echo "==> Starting the bot"
docker compose pull
docker compose $PROFILE up -d

echo
echo "The bot is starting. The first start downloads the malware signatures (a few minutes)."
echo
echo "=== Build this address into the desktop app (then publish the new installer) ==="
echo "    SENTRIX_RELAY_URL=https://$DOMAIN"
echo "    SENTRIX_BOT_USERNAME=<your bot's name without the @>"
echo "    Put these two lines in .sentrix-dev\bot.env on your computer and run scripts\build-release.ps1."
echo "    Open ports 80 and 443 in the provider's firewall panel if it has one."
echo
echo "Watch it:        docker compose -f $DIR/docker-compose.yml logs -f bot"
echo "Stop the copy on your own computer first (scripts\\install-bot-autostart.ps1 -Remove): only one program may run a bot at a time."
