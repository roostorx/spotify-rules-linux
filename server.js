const express = require("express");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

// ═══════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════
const PORT = process.env.PORT || 8777;
const REDIRECT_URI = process.env.REDIRECT_URI || `http://127.0.0.1:${PORT}/callback`;
const POLL_INTERVAL = 2000; // ms

// ═══════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════
const db = new Database(path.join(__dirname, "spotify-rules.db"));
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    spotify_id TEXT,
    display_name TEXT,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    client_id TEXT NOT NULL,
    token_expires_at INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    trigger_track_id TEXT NOT NULL,
    trigger_track_name TEXT,
    trigger_track_artist TEXT,
    trigger_track_image TEXT,
    trigger_track_duration INTEGER DEFAULT 0,
    fire_count INTEGER DEFAULT 0,
    last_fired_at INTEGER,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS rule_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    track_uri TEXT NOT NULL,
    track_id TEXT NOT NULL,
    track_name TEXT,
    track_artist TEXT,
    track_image TEXT,
    track_duration INTEGER DEFAULT 0,
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS playlists (
    id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    name TEXT,
    image TEXT,
    track_count INTEGER DEFAULT 0,
    owner TEXT,
    description TEXT,
    last_synced_at INTEGER,
    PRIMARY KEY (id, user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS playlist_tracks (
    playlist_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    track_id TEXT NOT NULL,
    track_name TEXT,
    track_artist TEXT,
    track_image TEXT,
    track_album TEXT,
    track_duration INTEGER DEFAULT 0,
    position INTEGER DEFAULT 0,
    added_at TEXT,
    PRIMARY KEY (playlist_id, track_id, user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE INDEX IF NOT EXISTS idx_pt_track ON playlist_tracks(track_id, user_id);
  CREATE INDEX IF NOT EXISTS idx_pt_playlist ON playlist_tracks(playlist_id, user_id);

  CREATE TABLE IF NOT EXISTS sync_status (
    user_id TEXT PRIMARY KEY,
    status TEXT DEFAULT 'idle',
    progress_current INTEGER DEFAULT 0,
    progress_total INTEGER DEFAULT 0,
    message TEXT,
    started_at INTEGER,
    completed_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Migration: add fire_count to existing databases
try { db.exec("ALTER TABLE rules ADD COLUMN fire_count INTEGER DEFAULT 0"); } catch {}

// Prepared statements
const stmts = {
  getUser: db.prepare("SELECT * FROM users WHERE id = ?"),
  getUserBySpotifyId: db.prepare("SELECT * FROM users WHERE spotify_id = ?"),
  upsertUser: db.prepare(`
    INSERT INTO users (id, spotify_id, display_name, access_token, refresh_token, client_id, token_expires_at, updated_at)
    VALUES (@id, @spotify_id, @display_name, @access_token, @refresh_token, @client_id, @token_expires_at, unixepoch())
    ON CONFLICT(id) DO UPDATE SET
      access_token=@access_token, refresh_token=COALESCE(@refresh_token, users.refresh_token),
      token_expires_at=@token_expires_at, display_name=@display_name, updated_at=unixepoch()
  `),
  updateTokens: db.prepare("UPDATE users SET access_token=?, refresh_token=COALESCE(?, refresh_token), token_expires_at=?, updated_at=unixepoch() WHERE id=?"),
  getRules: db.prepare("SELECT * FROM rules WHERE user_id = ? ORDER BY created_at DESC"),
  getRule: db.prepare("SELECT * FROM rules WHERE id = ? AND user_id = ?"),
  insertRule: db.prepare("INSERT INTO rules (id, user_id, trigger_track_id, trigger_track_name, trigger_track_artist, trigger_track_image, trigger_track_duration) VALUES (?,?,?,?,?,?,?)"),
  deleteRule: db.prepare("DELETE FROM rules WHERE id = ? AND user_id = ?"),
  toggleRule: db.prepare("UPDATE rules SET enabled = ? WHERE id = ? AND user_id = ?"),
  setRuleFired: db.prepare("UPDATE rules SET last_fired_at = unixepoch(), fire_count = COALESCE(fire_count, 0) + 1 WHERE id = ?"),
  getActions: db.prepare("SELECT * FROM rule_actions WHERE rule_id = ? ORDER BY position"),
  insertAction: db.prepare("INSERT INTO rule_actions (rule_id, position, track_uri, track_id, track_name, track_artist, track_image, track_duration) VALUES (?,?,?,?,?,?,?,?)"),
  deleteActions: db.prepare("DELETE FROM rule_actions WHERE rule_id = ?"),
  getAllActiveUsers: db.prepare("SELECT * FROM users WHERE access_token IS NOT NULL"),
  getEnabledRules: db.prepare("SELECT * FROM rules WHERE user_id = ? AND enabled = 1"),
  deleteUser: db.prepare("DELETE FROM users WHERE id = ?"),

  // Playlist sync
  upsertPlaylist: db.prepare(`
    INSERT INTO playlists (id, user_id, name, image, track_count, owner, description, last_synced_at)
    VALUES (?,?,?,?,?,?,?,unixepoch())
    ON CONFLICT(id, user_id) DO UPDATE SET
      name=excluded.name, image=excluded.image, track_count=excluded.track_count,
      owner=excluded.owner, description=excluded.description, last_synced_at=unixepoch()
  `),
  clearPlaylistTracks: db.prepare("DELETE FROM playlist_tracks WHERE playlist_id = ? AND user_id = ?"),
  insertPlaylistTrack: db.prepare(`
    INSERT OR REPLACE INTO playlist_tracks (playlist_id, user_id, track_id, track_name, track_artist, track_image, track_album, track_duration, position, added_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)
  `),
  getPlaylists: db.prepare("SELECT * FROM playlists WHERE user_id = ? ORDER BY name COLLATE NOCASE"),
  clearAllPlaylists: db.prepare("DELETE FROM playlists WHERE user_id = ?"),
  clearAllPlaylistTracks: db.prepare("DELETE FROM playlist_tracks WHERE user_id = ?"),

  // Library queries
  getTrackPlaylists: db.prepare(`
    SELECT pt.track_id, pt.track_name, pt.track_artist, pt.track_image, pt.track_album, pt.track_duration,
           p.id as playlist_id, p.name as playlist_name, p.image as playlist_image
    FROM playlist_tracks pt
    JOIN playlists p ON p.id = pt.playlist_id AND p.user_id = pt.user_id
    WHERE pt.track_id = ? AND pt.user_id = ?
  `),
  getAllTracksAggregated: db.prepare(`
    SELECT track_id, track_name, track_artist, track_image, track_album, track_duration,
           COUNT(DISTINCT playlist_id) as playlist_count,
           GROUP_CONCAT(DISTINCT playlist_id) as playlist_ids
    FROM playlist_tracks
    WHERE user_id = ?
    GROUP BY track_id
    ORDER BY playlist_count DESC, track_name COLLATE NOCASE
  `),
  searchLibrary: db.prepare(`
    SELECT track_id, track_name, track_artist, track_image, track_album, track_duration,
           COUNT(DISTINCT playlist_id) as playlist_count,
           GROUP_CONCAT(DISTINCT playlist_id) as playlist_ids
    FROM playlist_tracks
    WHERE user_id = ? AND (track_name LIKE ? OR track_artist LIKE ? OR track_album LIKE ?)
    GROUP BY track_id
    ORDER BY playlist_count DESC, track_name COLLATE NOCASE
    LIMIT 100
  `),
  getLibraryStats: db.prepare(`
    SELECT
      (SELECT COUNT(DISTINCT track_id) FROM playlist_tracks WHERE user_id = ?) as unique_tracks,
      (SELECT COUNT(*) FROM playlists WHERE user_id = ?) as total_playlists,
      (SELECT COUNT(*) FROM playlist_tracks WHERE user_id = ?) as total_entries
  `),

  // Sync status
  upsertSyncStatus: db.prepare(`
    INSERT INTO sync_status (user_id, status, progress_current, progress_total, message, started_at)
    VALUES (?, ?, ?, ?, ?, unixepoch())
    ON CONFLICT(user_id) DO UPDATE SET
      status=excluded.status, progress_current=excluded.progress_current,
      progress_total=excluded.progress_total, message=excluded.message,
      started_at=CASE WHEN excluded.status='syncing' THEN unixepoch() ELSE sync_status.started_at END,
      completed_at=CASE WHEN excluded.status='done' THEN unixepoch() ELSE NULL END
  `),
  getSyncStatus: db.prepare("SELECT * FROM sync_status WHERE user_id = ?"),
};

// ═══════════════════════════════════════
// SPOTIFY API HELPERS
// ═══════════════════════════════════════
async function spotifyFetch(endpoint, token, opts = {}) {
  const r = await fetch(`https://api.spotify.com/v1${endpoint}`, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, ...opts.headers },
  });
  if (r.status === 204) return null;
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`Spotify ${r.status}: ${body}`);
  }
  return r.json();
}

async function refreshAccessToken(user) {
  if (!user.refresh_token || !user.client_id) return false;
  try {
    const r = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: user.client_id,
        grant_type: "refresh_token",
        refresh_token: user.refresh_token,
      }),
    });
    const data = await r.json();
    if (data.access_token) {
      const expiresAt = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);
      stmts.updateTokens.run(data.access_token, data.refresh_token || null, expiresAt, user.id);
      user.access_token = data.access_token;
      if (data.refresh_token) user.refresh_token = data.refresh_token;
      user.token_expires_at = expiresAt;
      return true;
    }
  } catch (e) {
    console.error(`  ❌ Refresh failed for ${user.display_name || user.id}: ${e.message}`);
  }
  return false;
}

async function ensureValidToken(user) {
  const now = Math.floor(Date.now() / 1000);
  // Refresh if token expires within 5 minutes
  if (user.token_expires_at && user.token_expires_at - now < 300) {
    await refreshAccessToken(user);
  }
  return user.access_token;
}

// ═══════════════════════════════════════
// MONITORING ENGINE
// ═══════════════════════════════════════
// Per-user monitoring state (in memory)
// armed state now tracks whether we've queued and what track we expect next
const monitorState = new Map();

function getMonitorState(userId) {
  if (!monitorState.has(userId)) {
    monitorState.set(userId, {
      lastTrackId: null,
      armed: new Map(),   // ruleId -> { triggerTrackId, queued: bool, expectedTrackId }
      fired: new Set(),   // "ruleId-triggerTrackId" 
    });
  }
  return monitorState.get(userId);
}

async function pollUser(user) {
  try {
    const token = await ensureValidToken(user);
    const pb = await spotifyFetch("/me/player", token);

    if (!pb?.item || !pb.is_playing) return;

    const ms = getMonitorState(user.id);
    const currentId = pb.item.id;
    const progress = pb.progress_ms || 0;
    const duration = pb.item.duration_ms || 0;
    const remaining = duration - progress;
    const trackChanged = ms.lastTrackId && ms.lastTrackId !== currentId;

    // Clear fired state for tracks no longer playing
    if (trackChanged) {
      for (const key of ms.fired) {
        const ruleTrackId = key.split("-").pop();
        if (ruleTrackId !== currentId) ms.fired.delete(key);
      }
    }

    const rules = stmts.getEnabledRules.all(user.id);

    // Phase 1: ARM — detect trigger track, immediately queue the action track
    for (const rule of rules) {
      if (rule.trigger_track_id !== currentId) continue;
      const firedKey = `${rule.id}-${currentId}`;
      if (ms.fired.has(firedKey) || ms.armed.has(rule.id)) continue;
      if (progress < 15000) {
        const actions = stmts.getActions.all(rule.id);
        if (actions.length === 0) continue;

        // Queue the first action track immediately for smooth transition
        let queued = false;
        try {
          await spotifyFetch(`/me/player/queue?uri=${encodeURIComponent(actions[0].track_uri)}`, token, { method: "POST" });
          queued = true;
          console.log(`  🎯 Armed + Queued: "${rule.trigger_track_name}" → "${actions[0].track_name}" for ${user.display_name || user.id}`);
        } catch (e) {
          console.log(`  🎯 Armed (queue failed, will force-play): "${rule.trigger_track_name}" for ${user.display_name || user.id}`);
        }

        ms.armed.set(rule.id, {
          triggerTrackId: currentId,
          queued,
          expectedTrackId: actions[0].track_id,
        });
      }
    }

    // Phase 2: VERIFY — when the trigger track ends, check if the right track is playing
    for (const rule of rules) {
      if (!ms.armed.has(rule.id)) continue;
      const state = ms.armed.get(rule.id);
      const triggerIsPlaying = currentId === state.triggerTrackId;
      const songEnded = !triggerIsPlaying && trackChanged;

      if (songEnded) {
        ms.armed.delete(rule.id);
        ms.fired.add(`${rule.id}-${state.triggerTrackId}`);

        const actions = stmts.getActions.all(rule.id);
        if (actions.length === 0) continue;

        const correctTrackPlaying = currentId === state.expectedTrackId;

        if (correctTrackPlaying) {
          // Spotify naturally transitioned to our queued track — perfect!
          console.log(`  ✅ Smooth transition: "${actions[0].track_name}" playing naturally for ${user.display_name || user.id}`);
        } else {
          // Wrong track is playing — force-play our action track
          try {
            await spotifyFetch("/me/player/play", token, {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ uris: [actions[0].track_uri] }),
            });
            console.log(`  ▶ Force-played: "${actions[0].track_name}" (queue was overridden) for ${user.display_name || user.id}`);
          } catch (e) {
            console.error(`  ❌ Force-play failed: ${e.message}`);
          }
        }

        // Queue remaining action tracks (2nd, 3rd, etc.)
        for (let i = 1; i < actions.length; i++) {
          try {
            await spotifyFetch(`/me/player/queue?uri=${encodeURIComponent(actions[i].track_uri)}`, token, { method: "POST" });
            console.log(`  ✅ Queued: "${actions[i].track_name}"`);
          } catch (e) {
            console.error(`  ❌ Queue failed: "${actions[i].track_name}": ${e.message}`);
          }
        }

        stmts.setRuleFired.run(rule.id);
      }
    }

    ms.lastTrackId = currentId;

  } catch (e) {
    if (e.message.includes("401")) {
      const refreshed = await refreshAccessToken(user);
      if (!refreshed) {
        console.error(`  ⚠️ Auth failed for ${user.display_name || user.id}, removing from monitoring`);
      }
    } else if (!e.message.includes("502") && !e.message.includes("503")) {
      // Don't log transient Spotify errors
      console.error(`  Poll error for ${user.display_name || user.id}: ${e.message}`);
    }
  }
}

// Main monitoring loop
let monitorInterval = null;
function startMonitoring() {
  if (monitorInterval) return;
  console.log("  🔄 Monitoring engine started");
  monitorInterval = setInterval(async () => {
    const users = stmts.getAllActiveUsers.all();
    // Poll all users in parallel
    await Promise.allSettled(users.map(u => pollUser(u)));
  }, POLL_INTERVAL);
}

// ═══════════════════════════════════════
// PKCE HELPERS
// ═══════════════════════════════════════
function randomString(len) { return crypto.randomBytes(len).toString("base64url").slice(0, len); }
function sha256(str) { return crypto.createHash("sha256").update(str).digest(); }
function base64url(buf) { return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }

// Store PKCE verifiers per state param
const pendingAuth = new Map();

// ═══════════════════════════════════════
// EXPRESS APP
// ═══════════════════════════════════════
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Auth: initiate (used by web UI) ──
app.get("/login", (req, res) => {
  const clientId = req.query.client_id;
  if (!clientId) return res.status(400).json({ error: "client_id required" });

  const verifier = randomString(64);
  const challenge = base64url(sha256(verifier));
  const state = randomString(32);

  pendingAuth.set(state, { verifier, clientId });
  setTimeout(() => pendingAuth.delete(state), 600000); // 10 min expiry

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: "user-read-playback-state user-modify-playback-state user-read-currently-playing playlist-read-private playlist-read-collaborative",
    code_challenge_method: "S256",
    code_challenge: challenge,
    state,
  });
  res.redirect(`https://accounts.spotify.com/authorize?${params}`);
});

// ── Auth: callback ──
app.get("/callback", async (req, res) => {
  const { code, error, state } = req.query;
  if (error) return res.redirect(`/?error=${encodeURIComponent(error)}`);

  const pending = pendingAuth.get(state);
  if (!pending) return res.redirect("/?error=invalid_state");
  pendingAuth.delete(state);

  try {
    const r = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: pending.clientId,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: pending.verifier,
      }),
    });
    const data = await r.json();

    if (!data.access_token) {
      return res.redirect(`/?error=${encodeURIComponent(data.error_description || "token_failed")}`);
    }

    // Get user profile
    const profile = await spotifyFetch("/me", data.access_token);
    const userId = profile.id;
    const expiresAt = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);

    stmts.upsertUser.run({
      id: userId,
      spotify_id: userId,
      display_name: profile.display_name || userId,
      access_token: data.access_token,
      refresh_token: data.refresh_token || null,
      client_id: pending.clientId,
      token_expires_at: expiresAt,
    });

    // Set a cookie-like token for the web UI (simple approach)
    res.redirect(`/?auth=success&user_id=${encodeURIComponent(userId)}`);

  } catch (e) {
    console.error("Callback error:", e);
    res.redirect("/?error=server_error");
  }
});

// ── API Auth: exchange code (used by iOS app) ──
// iOS sends: { client_id, code, code_verifier, redirect_uri }
app.post("/api/auth/token", async (req, res) => {
  const { client_id, code, code_verifier, redirect_uri } = req.body;
  if (!client_id || !code || !code_verifier || !redirect_uri) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    const r = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id,
        grant_type: "authorization_code",
        code,
        redirect_uri,
        code_verifier,
      }),
    });
    const data = await r.json();

    if (!data.access_token) {
      return res.status(400).json({ error: data.error_description || data.error || "token_failed" });
    }

    const profile = await spotifyFetch("/me", data.access_token);
    const userId = profile.id;
    const expiresAt = Math.floor(Date.now() / 1000) + (data.expires_in || 3600);

    stmts.upsertUser.run({
      id: userId,
      spotify_id: userId,
      display_name: profile.display_name || userId,
      access_token: data.access_token,
      refresh_token: data.refresh_token || null,
      client_id,
      token_expires_at: expiresAt,
    });

    res.json({
      user_id: userId,
      display_name: profile.display_name,
      access_token: data.access_token,
      expires_in: data.expires_in,
    });

  } catch (e) {
    console.error("Token exchange error:", e);
    res.status(500).json({ error: "server_error" });
  }
});

// ── API: get user info + token (for web UI) ──
app.get("/api/token", (req, res) => {
  const userId = req.query.user_id;
  if (!userId) return res.status(401).json({ error: "no user_id" });
  const user = stmts.getUser.get(userId);
  if (!user) return res.status(401).json({ error: "not_found" });
  res.json({ access_token: user.access_token, user_id: user.id, display_name: user.display_name });
});

// ── API: refresh (for web UI) ──
app.get("/api/refresh", async (req, res) => {
  const userId = req.query.user_id;
  if (!userId) return res.status(401).json({ error: "no user_id" });
  const user = stmts.getUser.get(userId);
  if (!user) return res.status(401).json({ error: "not_found" });
  const ok = await refreshAccessToken(user);
  if (ok) res.json({ access_token: user.access_token });
  else res.status(401).json({ error: "refresh_failed" });
});

// ── API: logout ──
app.post("/api/auth/logout", (req, res) => {
  const userId = req.body.user_id;
  if (userId) {
    stmts.deleteUser.run(userId);
    monitorState.delete(userId);
  }
  res.json({ ok: true });
});

// ═══════════════════════════════════════
// RULES CRUD API
// ═══════════════════════════════════════

// Auth middleware — extracts user_id from header or query
function requireUser(req, res, next) {
  const userId = req.headers["x-user-id"] || req.query.user_id;
  if (!userId) return res.status(401).json({ error: "user_id required" });
  const user = stmts.getUser.get(userId);
  if (!user) return res.status(401).json({ error: "user not found" });
  req.user = user;
  next();
}

// GET /api/rules
app.get("/api/rules", requireUser, (req, res) => {
  const rules = stmts.getRules.all(req.user.id);
  const result = rules.map(r => ({
    ...r,
    enabled: !!r.enabled,
    actions: stmts.getActions.all(r.id),
  }));
  res.json(result);
});

// POST /api/rules
app.post("/api/rules", requireUser, (req, res) => {
  const { trigger, actions } = req.body;
  if (!trigger?.id || !actions?.length) {
    return res.status(400).json({ error: "trigger and actions required" });
  }

  const ruleId = crypto.randomUUID();

  db.transaction(() => {
    stmts.insertRule.run(
      ruleId,
      req.user.id,
      trigger.id,
      trigger.name || null,
      trigger.artist || null,
      trigger.image || null,
      trigger.duration || 0
    );

    actions.forEach((a, i) => {
      stmts.insertAction.run(
        ruleId, i,
        a.uri || `spotify:track:${a.id}`,
        a.id,
        a.name || null,
        a.artist || null,
        a.image || null,
        a.duration || 0
      );
    });
  })();

  const rule = stmts.getRule.get(ruleId, req.user.id);
  const ruleActions = stmts.getActions.all(ruleId);

  res.json({ ...rule, enabled: !!rule.enabled, actions: ruleActions });
});

// DELETE /api/rules/:id
app.delete("/api/rules/:id", requireUser, (req, res) => {
  stmts.deleteActions.run(req.params.id);
  stmts.deleteRule.run(req.params.id, req.user.id);
  if (monitorState.has(req.user.id)) {
    const ms = monitorState.get(req.user.id);
    ms.armed.delete(req.params.id);
  }
  res.json({ ok: true });
});

// PATCH /api/rules/:id/toggle
app.patch("/api/rules/:id/toggle", requireUser, (req, res) => {
  const rule = stmts.getRule.get(req.params.id, req.user.id);
  if (!rule) return res.status(404).json({ error: "not found" });
  const newState = rule.enabled ? 0 : 1;
  stmts.toggleRule.run(newState, req.params.id, req.user.id);
  res.json({ enabled: !!newState });
});

// GET /api/status — monitoring status
app.get("/api/status", requireUser, (req, res) => {
  const ms = monitorState.get(req.user.id);
  const rules = stmts.getEnabledRules.all(req.user.id);
  res.json({
    monitoring: !!monitorInterval,
    active_rules: rules.length,
    armed_rules: ms ? [...ms.armed.keys()] : [],
  });
});

// ═══════════════════════════════════════
// SEARCH PROXY (for iOS app)
// ═══════════════════════════════════════
app.get("/api/search", requireUser, async (req, res) => {
  const q = req.query.q;
  if (!q) return res.json([]);

  try {
    const token = await ensureValidToken(req.user);
    const data = await spotifyFetch(`/search?q=${encodeURIComponent(q)}&type=track&limit=10`, token);
    const tracks = (data?.tracks?.items || []).map(t => ({
      id: t.id,
      uri: t.uri,
      name: t.name,
      artist: t.artists.map(a => a.name).join(", "),
      image: t.album?.images?.[1]?.url || t.album?.images?.[0]?.url || null,
      image_small: t.album?.images?.[2]?.url || null,
      duration: t.duration_ms,
    }));
    res.json(tracks);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/track/:id — resolve single track
app.get("/api/track/:id", requireUser, async (req, res) => {
  try {
    const token = await ensureValidToken(req.user);
    const t = await spotifyFetch(`/tracks/${req.params.id}`, token);
    res.json({
      id: t.id,
      uri: t.uri,
      name: t.name,
      artist: t.artists.map(a => a.name).join(", "),
      image: t.album?.images?.[1]?.url || t.album?.images?.[0]?.url || null,
      image_small: t.album?.images?.[2]?.url || null,
      duration: t.duration_ms,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/playback — current playback
app.get("/api/playback", requireUser, async (req, res) => {
  try {
    const token = await ensureValidToken(req.user);
    const pb = await spotifyFetch("/me/player", token);
    if (!pb) return res.json(null);
    res.json({
      is_playing: pb.is_playing,
      track: pb.item ? {
        id: pb.item.id,
        name: pb.item.name,
        artist: pb.item.artists.map(a => a.name).join(", "),
        image: pb.item.album?.images?.[0]?.url || null,
        duration: pb.item.duration_ms,
        progress: pb.progress_ms,
      } : null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════
// PLAYLIST SYNC ENGINE
// ═══════════════════════════════════════
const activeSyncs = new Set();

async function syncPlaylists(user) {
  if (activeSyncs.has(user.id)) return;
  activeSyncs.add(user.id);

  const updateStatus = (status, current, total, message) => {
    stmts.upsertSyncStatus.run(user.id, status, current, total, message);
  };

  try {
    const token = await ensureValidToken(user);
    updateStatus("syncing", 0, 0, "Fetching playlists...");
    console.log(`  📚 Starting playlist sync for ${user.display_name || user.id}`);

    // Step 1: Fetch all playlists
    let allPlaylists = [];
    let offset = 0;
    const limit = 50;

    while (true) {
      const data = await spotifyFetch(`/me/playlists?limit=${limit}&offset=${offset}`, token);
      if (!data?.items?.length) break;
      allPlaylists.push(...data.items);
      offset += limit;
      updateStatus("syncing", 0, 0, `Found ${allPlaylists.length} playlists...`);
      if (!data.next) break;
      // Small delay to be nice to rate limits
      await new Promise(r => setTimeout(r, 200));
    }

    const total = allPlaylists.length;
    console.log(`  📋 Found ${total} playlists`);
    updateStatus("syncing", 0, total, `Syncing 0 / ${total} playlists...`);

    // Step 2: Clear old data
    stmts.clearAllPlaylistTracks.run(user.id);
    stmts.clearAllPlaylists.run(user.id);

    // Step 3: Fetch tracks for each playlist
    const insertTracks = db.transaction((playlistId, userId, tracks) => {
      for (const t of tracks) {
        const track = t.item || t.track; // support both new (item) and old (track) response format
        if (!track?.id) continue; // skip local files, podcasts, etc.
        stmts.insertPlaylistTrack.run(
          playlistId, userId,
          track.id,
          track.name || null,
          track.artists?.map(a => a.name).join(", ") || null,
          track.album?.images?.[2]?.url || track.album?.images?.[0]?.url || null,
          track.album?.name || null,
          track.duration_ms || 0,
          t.position ?? 0,
          t.added_at || null
        );
      }
    });

    for (let i = 0; i < allPlaylists.length; i++) {
      const pl = allPlaylists[i];

      // Save playlist
      stmts.upsertPlaylist.run(
        pl.id, user.id,
        pl.name || "Untitled",
        pl.images?.[0]?.url || null,
        pl.items?.total || pl.tracks?.total || 0,
        pl.owner?.display_name || null,
        pl.description || null
      );

      updateStatus("syncing", i + 1, total, `Syncing ${i + 1} / ${total}: ${pl.name || "Untitled"}`);

      // Fetch all tracks in this playlist
      let trackOffset = 0;
      let allTracks = [];

      while (true) {
        try {
          const trackData = await spotifyFetch(
            `/playlists/${pl.id}/items?limit=100&offset=${trackOffset}&fields=items(added_at,item(id,name,duration_ms,artists(name),album(name,images))),next`,
            token
          );
          if (!trackData?.items?.length) break;

          // Add position info
          const items = trackData.items.map((item, idx) => ({
            ...item,
            position: trackOffset + idx,
          }));
          allTracks.push(...items);

          if (!trackData.next) break;
          trackOffset += 100;

          // Rate limit: pause between pages
          await new Promise(r => setTimeout(r, 300));
        } catch (e) {
          if (e.message.includes("429")) {
            console.log(`  ⏳ Rate limited, waiting 5s...`);
            await new Promise(r => setTimeout(r, 5000));
            continue; // retry same offset
          }
          console.error(`  ⚠️ Error fetching tracks for "${pl.name}": ${e.message}`);
          break;
        }
      }

      // Batch insert tracks
      insertTracks(pl.id, user.id, allTracks);

      // Pause between playlists
      await new Promise(r => setTimeout(r, 200));
    }

    const stats = stmts.getLibraryStats.get(user.id, user.id, user.id);
    const doneMsg = `Done! ${stats.unique_tracks} unique tracks across ${stats.total_playlists} playlists`;
    updateStatus("done", total, total, doneMsg);
    console.log(`  ✅ Sync complete: ${doneMsg}`);

  } catch (e) {
    console.error(`  ❌ Sync failed: ${e.message}`);
    updateStatus("error", 0, 0, `Sync failed: ${e.message}`);
  } finally {
    activeSyncs.delete(user.id);
  }
}

// ═══════════════════════════════════════
// LIBRARY API ENDPOINTS
// ═══════════════════════════════════════

// POST /api/library/sync — start a playlist sync
app.post("/api/library/sync", requireUser, async (req, res) => {
  if (activeSyncs.has(req.user.id)) {
    return res.json({ status: "already_syncing" });
  }
  // Start sync in background
  syncPlaylists(req.user);
  res.json({ status: "started" });
});

// GET /api/library/sync-status — check sync progress
app.get("/api/library/sync-status", requireUser, (req, res) => {
  const status = stmts.getSyncStatus.get(req.user.id);
  res.json(status || { status: "idle", progress_current: 0, progress_total: 0, message: "Never synced" });
});

// GET /api/library/stats — library overview
app.get("/api/library/stats", requireUser, (req, res) => {
  const stats = stmts.getLibraryStats.get(req.user.id, req.user.id, req.user.id);
  const syncStatus = stmts.getSyncStatus.get(req.user.id);
  res.json({
    unique_tracks: stats?.unique_tracks || 0,
    total_playlists: stats?.total_playlists || 0,
    total_entries: stats?.total_entries || 0,
    last_synced: syncStatus?.completed_at || null,
  });
});

// GET /api/library/tracks — all tracks sorted by playlist count
app.get("/api/library/tracks", requireUser, (req, res) => {
  const q = req.query.q?.trim();
  const page = parseInt(req.query.page) || 0;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);

  let tracks;
  if (q) {
    const like = `%${q}%`;
    tracks = stmts.searchLibrary.all(req.user.id, like, like, like);
  } else {
    tracks = stmts.getAllTracksAggregated.all(req.user.id);
  }

  // Get playlist name lookup
  const playlists = stmts.getPlaylists.all(req.user.id);
  const playlistMap = Object.fromEntries(playlists.map(p => [p.id, p]));

  // Paginate
  const total = tracks.length;
  const sliced = tracks.slice(page * limit, (page + 1) * limit);

  // Expand playlist_ids to full objects
  const result = sliced.map(t => ({
    track_id: t.track_id,
    name: t.track_name,
    artist: t.track_artist,
    image: t.track_image,
    album: t.track_album,
    duration: t.track_duration,
    playlist_count: t.playlist_count,
    playlists: (t.playlist_ids || "").split(",").filter(Boolean).map(pid => {
      const p = playlistMap[pid];
      return p ? { id: p.id, name: p.name, image: p.image } : { id: pid, name: "Unknown" };
    }),
  }));

  res.json({ tracks: result, total, page, limit });
});

// GET /api/library/track/:id/playlists — which playlists contain this track
app.get("/api/library/track/:id/playlists", requireUser, (req, res) => {
  const rows = stmts.getTrackPlaylists.all(req.params.id, req.user.id);
  if (rows.length === 0) return res.json({ track: null, playlists: [] });
  res.json({
    track: {
      id: rows[0].track_id,
      name: rows[0].track_name,
      artist: rows[0].track_artist,
      image: rows[0].track_image,
      album: rows[0].track_album,
      duration: rows[0].track_duration,
    },
    playlists: rows.map(r => ({
      id: r.playlist_id,
      name: r.playlist_name,
      image: r.playlist_image,
    })),
  });
});

// GET /api/library/playlists — all playlists
app.get("/api/library/playlists", requireUser, (req, res) => {
  const playlists = stmts.getPlaylists.all(req.user.id);
  res.json(playlists);
});

// ═══════════════════════════════════════
// START
// ═══════════════════════════════════════
app.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("  ⚡ Spotify Rules Server");
  console.log(`  ➜ http://127.0.0.1:${PORT}`);
  console.log("");

  // Start the monitoring engine
  startMonitoring();

  const userCount = stmts.getAllActiveUsers.all().length;
  if (userCount > 0) {
    console.log(`  👤 Monitoring ${userCount} user(s)`);
  } else {
    console.log("  👤 No users yet — connect via the app or web UI");
  }
  console.log("");
});
