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
  read -r -p "Domain name pointing at this server, for HTTPS (press Enter to skip): " DOMAIN < /dev/tty || DOMAIN=""
  umask 077
  printf 'SENTRIX_BOT_TOKEN=%s\nDOMAIN=%s\n' "$TOKEN" "$DOMAIN" > .env
  chmod 600 .env
  unset TOKEN
fi

PROFILE=""
if grep -q '^DOMAIN=.\+' .env; then PROFILE="--profile https"; fi

echo "==> Starting the bot"
docker compose pull
docker compose $PROFILE up -d

echo
echo "The bot is starting. The first start downloads the malware signatures (a few minutes)."
echo "Watch it:        docker compose -f $DIR/docker-compose.yml logs -f bot"
echo "Stop the copy on your own computer first (scripts\\install-bot-autostart.ps1 -Remove): only one program may run a bot at a time."
