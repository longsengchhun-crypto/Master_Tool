# Running the bot 24 hours a day

A program on your own computer stops when the computer sleeps, loses the internet or is switched off. For the bot to protect
groups around the clock, it has to run on a **server that is always on**. The bot is built for that: a container image published
automatically, one install command, and it updates itself.

## What you need (the part only you can do)

1. **A server.** Any small Linux VPS (Ubuntu 22.04/24.04 or Debian 12): **2 GB of memory at least** (the malware engine alone uses
   about 1.3 GB), 2 or more CPU cores, 20 GB disk. Typical cost: about 4 to 8 USD a month (Hetzner, DigitalOcean, Vultr, Contabo),
   or a free-tier VM from a cloud provider. This needs your account and your payment method; it cannot be created from here.
2. **The bot token** from @BotFather (the same one you use now).
3. *Optional:* your own domain name. If you give none, the installer uses a free automatic HTTPS name (`<server-ip>.sslip.io`).
   **The HTTPS address is required**: the desktop app links to the bot, fetches files to check and returns verdicts through it.
   An app built with `http://127.0.0.1:8787` only works on the one computer that runs the bot.

## Install (about five minutes)

1. **Stop the copy on your computer** (only one program may run a bot): in PowerShell,
   `scripts\install-bot-autostart.ps1 -Remove`.
2. On the server, as root:
   ```
   curl -fsSL https://raw.githubusercontent.com/longsengchhun-crypto/Master_Tool/main/deploy/install.sh | sudo bash
   ```
   It installs Docker, asks for the token (hidden) and optionally a domain, and starts the bot.
3. **Build the address into the app.** The installer ends by printing `SENTRIX_RELAY_URL=https://...`. Put that line and
   `SENTRIX_BOT_USERNAME=YourBot` in `.sentrix-devot.env` on your computer, run `scriptsuild-release.ps1`, then publish the
   release. Customers' apps update themselves. Open ports 80 and 443 in the provider's firewall panel if it has one.
4. The first start downloads the malware signatures (a few minutes). Watch: `docker compose -f /opt/sentrix/docker-compose.yml logs -f bot`.
   When it prints `running`, send a file to a protected group.

Make the image public once: GitHub > your profile > Packages > `sentrix-bot` > Package settings > Change visibility > Public.
(Otherwise the server cannot download it without logging in.)

## What keeps it running and current

* `restart: unless-stopped`: the bot comes back after a crash or a reboot, with no one signed in.
* **Watchtower** checks every 10 minutes for a newer image and swaps it in, so every change pushed to `main` that touches the
  service reaches the server by itself (CI builds and tests on Linux first; a failing test publishes nothing).
* Malware signatures refresh every 2 hours inside the bot.
* The data (database, signatures) lives in a Docker volume and survives updates.

## Scale, honestly

One server is one program: it checks as many files at once as it has CPU cores (`SENTRIX_DOC_WORKERS` overrides), at roughly 0.4 s
for a small file and a few seconds for a big archive. That comfortably serves **many thousands of active groups** on a 4-core
machine. It is **not** unlimited: 100 000 *active* users posting files all day would need a bigger machine, and past that the
design has to be split across several servers (Telegram webhooks, a shared queue, one ClamAV per node). That is real work that
should be done when the traffic is real; the numbers will tell you when. Watch CPU and the `[time]` lines in the log.

## What still stops when a computer is off

**Only features that run on the user's computer:** the desktop app's real-time folder protection and *personal account*
protection (the Telegram login stays on the person's PC by design and by your decision). Group files are also checked on the group owner's
computer (your decision: no customer file is scanned or kept on the server), so a file waits until that person's app is running.
Your own computer is not needed for anything once the server runs. The server needs less power than the table above if
`SENTRIX_EDGE_SCAN` is left at its default, but keep 2 GB for headroom.

## Other ways to host

Any host that runs Docker works: copy `deploy/docker-compose.yml` and `.env`, run `docker compose up -d`. For a host that runs a single
container (Fly.io, Railway, Render), use the image `ghcr.io/longsengchhun-crypto/sentrix-bot:latest`, mount a volume at `/data`, set
`SENTRIX_BOT_TOKEN` as a secret, and give it at least 2 GB of memory.
