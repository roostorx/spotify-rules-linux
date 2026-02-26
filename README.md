# ⚡ Spotify Rules — Linux Server

24/7 monitoring server with web UI. No app needed — manage everything from your browser.

## Setup

```bash
# 1. Install Node.js 18+ if needed
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install -y nodejs

# 2. Install dependencies
cd spotify-rules-linux
npm install

# 3. Run it
npm start
```

Opens at `http://127.0.0.1:8888` (or your server's IP on port 8888).

## Spotify App Setup

1. Go to [developer.spotify.com/dashboard](https://developer.spotify.com/dashboard)
2. Create an app
3. Set redirect URI to: `http://YOUR_SERVER_IP:8888/callback`
4. Copy your Client ID

If running on a LAN machine (e.g. `192.168.1.50`):
```bash
REDIRECT_URI=http://192.168.1.50:8888/callback npm start
```

## Run as a Service (systemd)

```bash
sudo nano /etc/systemd/system/spotify-rules.service
```

```ini
[Unit]
Description=Spotify Rules Engine
After=network.target

[Service]
ExecStart=/usr/bin/node /path/to/spotify-rules-linux/server.js
WorkingDirectory=/path/to/spotify-rules-linux
Restart=always
User=youruser
Environment=REDIRECT_URI=http://YOUR_IP:8888/callback

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable spotify-rules
sudo systemctl start spotify-rules
```

## What It Does

- Monitors your Spotify playback every 2 seconds
- When a trigger song is detected, arms the rule
- When the trigger song ends, force-plays the next track via PUT /me/player/play
- Rules persist in SQLite — survives restarts
- Auto-refreshes Spotify tokens — no re-auth needed

## Remote Access (SSH Tunnel)

If the server is on a remote machine (e.g. `192.168.1.119`), access it from your Mac via SSH tunnel:

```bash
ssh -L 8777:127.0.0.1:8777 -N -f ken@192.168.1.119
```

Then open `http://localhost:8777` in your browser.

## Files

```
server.js          — Express server + monitoring engine + API
public/index.html  — Web UI
spotify-rules.db   — SQLite database (created on first run)
```
