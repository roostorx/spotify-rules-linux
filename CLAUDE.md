# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A 24/7 Node.js server that monitors Spotify playback and automatically plays specific tracks when trigger songs are detected. Users create rules like "When song X plays, automatically queue songs Y, Z afterward."

## Common Commands

```bash
# Install dependencies
npm install

# Run server (development with auto-reload)
npm run dev

# Run server (production)
npm start

# Run with custom redirect URI (for LAN access)
REDIRECT_URI=http://192.168.1.50:8888/callback npm start

# Check database directly
sqlite3 spotify-rules.db
```

**Server Access:**
- Default: `http://127.0.0.1:8888`
- Configure redirect URI in Spotify Developer Dashboard to match your setup

## Architecture

### Monitoring Engine (`server.js:250-388`)

The core monitoring loop runs every 2 seconds and uses a **two-phase ARM/VERIFY system**:

1. **ARM Phase** (lines 289-314)
   - Detects when trigger track starts (within first 15 seconds)
   - Immediately queues the first action track for smooth transition
   - Stores armed state: `{ triggerTrackId, queued: bool, expectedTrackId }`

2. **VERIFY Phase** (lines 317-361)
   - When trigger track ends (track changes), checks what's actually playing
   - If correct track is playing: log success (queue worked)
   - If wrong track is playing: force-play the action track via PUT `/me/player/play`
   - Queue remaining action tracks (2nd, 3rd, etc.)
   - Mark rule as fired and increment fire counter

**Per-User State** (`monitorState` Map):
- `lastTrackId`: Previous track ID for detecting transitions
- `armed`: Map of ruleId → armed state
- `fired`: Set of "ruleId-trackId" to prevent re-firing same trigger

### Database Schema (`server.js:19-101`)

**Core Tables:**
- `users`: Spotify credentials, access/refresh tokens, token expiry
- `rules`: Trigger track ID, enabled state, fire count, last fired timestamp
- `rule_actions`: Ordered list of tracks to play (position-based)

**Library Sync Tables:**
- `playlists`: User's playlists metadata
- `playlist_tracks`: All tracks from all playlists (for searching/browsing)
- `sync_status`: Background sync progress tracking

**Playlist Tracker Tables:**
- `tracked_playlists`: Source playlist ID, destination playlist ID, tracking state
- `tracked_playlist_tracks`: Known tracks for each tracked playlist (for additive diff)

**Listen History Tables:**
- `listens`: Every track play with timestamp, ms_played, artist/album/track info, source (live/import)
- Indexes on `(user_id, played_at)`, `(user_id, track_id)`, `(user_id, artist_name)`, `(user_id, album_name)`

**Key Indexes:**
- `idx_pt_track`: Fast lookup of which playlists contain a track
- `idx_pt_playlist`: Fast lookup of all tracks in a playlist

### Token Management (`server.js:211-245`)

- Tokens are auto-refreshed when they expire within 5 minutes (`ensureValidToken`)
- Refresh tokens are stored in database and reused across restarts
- PKCE flow used for OAuth (no client secret needed)
- `pendingAuth` Map stores PKCE verifiers during OAuth flow (10 min TTL)

### Playlist Sync Engine (`server.js:731-854`)

Background sync fetches all user playlists and tracks:
- Fetches playlists in batches of 50
- Fetches tracks in batches of 100 per playlist
- Rate limiting: 200-300ms between requests, 5s backoff on 429
- Clears old data before inserting new (full replace strategy)
- Updates `sync_status` table with real-time progress

## API Endpoints

### Authentication
- `GET /login?client_id=...` - Initiate PKCE OAuth flow
- `GET /callback` - OAuth callback (exchanges code for tokens)
- `POST /api/auth/token` - Exchange code for tokens (iOS app)
- `GET /api/refresh?user_id=...` - Manually refresh access token
- `POST /api/auth/logout` - Delete user and monitoring state

### Rules Management
- `GET /api/rules` - List all rules with actions
- `POST /api/rules` - Create rule (body: `{ trigger, actions }`)
- `DELETE /api/rules/:id` - Delete rule
- `PATCH /api/rules/:id/toggle` - Enable/disable rule
- `GET /api/status` - Monitoring status (active rules, armed rules)

### Library & Search
- `POST /api/library/sync` - Start background playlist sync
- `GET /api/library/sync-status` - Check sync progress
- `GET /api/library/stats` - Library overview (track count, playlist count)
- `GET /api/library/tracks?q=...&page=0&limit=50` - Search/browse library
- `GET /api/library/track/:id/playlists` - Which playlists contain this track
- `GET /api/search?q=...` - Proxy to Spotify search (returns top 10 tracks)
- `GET /api/track/:id` - Get single track metadata
- `GET /api/playback` - Current playback state

### Authentication Middleware
`requireUser` extracts `user_id` from `X-User-Id` header or `user_id` query param, validates user exists in database.

## Important Implementation Details

### Why Two-Phase ARM/VERIFY?

The initial approach was to queue tracks when the trigger ended, but Spotify's queue can be overridden (shuffle, user interaction, etc.). The two-phase system:
1. **Queues immediately** when trigger starts (best-case: smooth transition)
2. **Verifies and force-plays** if needed when trigger ends (fallback: always works)

This ensures rules fire reliably even when the queue is disrupted.

### Track Change Detection

Track changes are detected by comparing `currentId !== lastTrackId`. The `fired` Set prevents re-triggering the same rule on the same track until the track changes, but is cleared when different tracks play to allow re-arming.

### Database Transactions

Prepared statements (`stmts.*`) are used for all queries. Multi-step operations like creating rules use `db.transaction()` for atomicity (lines 599-621).

### WAL Mode

Database uses WAL (Write-Ahead Logging) mode for better concurrency - allows monitoring loop to read while API writes.

## Web UI (`public/index.html`)

Single-page app that:
- Handles Spotify OAuth flow
- Manages rules (create, delete, toggle)
- Displays current playback
- Browses synced library
- Shows sync progress

UI stores `user_id` in localStorage and passes it to all API calls.

## Running as a Service

Example systemd service (from README.md):

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

## Spotify API Scopes Required

- `user-read-playback-state` - Monitor current playback
- `user-modify-playback-state` - Queue and force-play tracks
- `user-read-currently-playing` - Read current track
- `playlist-read-private` - Read private playlists
- `playlist-read-collaborative` - Read collaborative playlists

## Development Notes

- Monitoring polls every 2 seconds (`POLL_INTERVAL = 2000`)
- All active users are polled in parallel (`Promise.allSettled`)
- Token refresh happens automatically before API calls
- Database file is created on first run
- Migration for `fire_count` column runs on startup (line 104)
- Transient Spotify errors (502, 503) are silently ignored
