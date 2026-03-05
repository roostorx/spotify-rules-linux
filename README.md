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

Opens at `http://127.0.0.1:8777` (or your server's IP on port 8777).

## Spotify App Setup

1. Go to [developer.spotify.com/dashboard](https://developer.spotify.com/dashboard)
2. Create an app
3. Set redirect URI to: `http://YOUR_SERVER_IP:8777/callback`
4. Copy your Client ID

If running on a LAN machine (e.g. `192.168.1.50`):
```bash
REDIRECT_URI=http://192.168.1.50:8777/callback npm start
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
Environment=REDIRECT_URI=http://YOUR_IP:8777/callback

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable spotify-rules
sudo systemctl start spotify-rules
```

## What It Does

### Rules Engine
- Monitors your Spotify playback every 2 seconds
- When a trigger song is detected, arms the rule
- When the trigger song ends, force-plays the next track via PUT /me/player/play
- Rules persist in SQLite — survives restarts
- Auto-refreshes Spotify tokens — no re-auth needed

### Playlist Tracker
- Track any Spotify playlist (including editorial/algorithmic playlists like "Chaos Anthems")
- Automatically creates a private archive playlist on your account
- Checks for changes every 5 minutes and adds new songs additively (never removes)
- Uses Spotify's embed page to read playlists, bypassing API restrictions on editorial playlists
- Paste any Spotify playlist URL in the Tracker tab to start tracking

### Listen History & Stats
- Automatically records every song you play (30+ second threshold) — runs 24/7 server-side, no UI needed
- Import Spotify extended streaming history (request from Privacy settings, supports `endsong_*.json` and `Streaming_History_Audio_*.json`)
- Deduplicates on import — safe to re-import files, old and new data merges cleanly
- Exclusion rules prevent unwanted listens from returning on re-import (e.g. fell asleep on repeat)
- **Stats dashboard** with:
  - Total plays, listen time (hours/days), unique tracks/artists/albums
  - Top tracks, artists, and albums — sortable by play count or total listen time
  - Time filtering: 7d / 30d / 90d / 6m / 1y / all time + custom date range
  - Day streaks (consecutive days listening) — current + longest with dates
  - Song streaks — most times on repeat + longest run of unique songs (60-min session gap)
  - Recent listens feed with source badges (live vs import)
  - Album art throughout, progress bars showing relative play counts

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
