import sqlite3
import json
import time
import os

DB_PATH = os.environ.get("FINGERPRINT_DB", "fingerprints.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS browser_profiles (
  browser_id            TEXT PRIMARY KEY,
  first_seen_at         INTEGER NOT NULL,
  last_seen_at          INTEGER NOT NULL,
  visit_count           INTEGER NOT NULL DEFAULT 1,
  current_confidence    REAL NOT NULL,
  ja4                   TEXT,
  webgl_renderer        TEXT,
  font_hash             TEXT,
  voice_hash            TEXT,
  stable_profile        TEXT NOT NULL,
  semi_stable_profile   TEXT NOT NULL,
  network_profile       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_prof_ja4       ON browser_profiles(ja4);
CREATE INDEX IF NOT EXISTS idx_prof_webgl     ON browser_profiles(webgl_renderer);
CREATE INDEX IF NOT EXISTS idx_prof_font      ON browser_profiles(font_hash);
CREATE INDEX IF NOT EXISTS idx_prof_voice     ON browser_profiles(voice_hash);
CREATE INDEX IF NOT EXISTS idx_prof_last_seen ON browser_profiles(last_seen_at);

CREATE TABLE IF NOT EXISTS visits (
  visit_id              INTEGER PRIMARY KEY AUTOINCREMENT,
  browser_id            TEXT NOT NULL,
  seen_at               INTEGER NOT NULL,
  match_score           REAL,
  is_new_browser        INTEGER NOT NULL,
  ja4                   TEXT,
  ja3_hash              TEXT,
  h2fp                  TEXT,
  ua_family             TEXT,
  ua_major              INTEGER,
  platform              TEXT,
  vendor                TEXT,
  webgl_renderer        TEXT,
  webgl_vendor          TEXT,
  webgl_render          TEXT,
  webgl_ext_hash        TEXT,
  webgl_caps_hash       TEXT,
  font_hash             TEXT,
  voice_hash            TEXT,
  voice_count           INTEGER,
  audio_hash            TEXT,
  css_supports_hash     TEXT,
  constructor_count     INTEGER,
  event_handler_count   INTEGER,
  intl_hash             TEXT,
  timezone              TEXT,
  timezone_offset       INTEGER,
  language              TEXT,
  max_touch_bucket      TEXT,
  cookie_enabled        INTEGER,
  reduced_motion        INTEGER,
  color_depth           INTEGER,
  pixel_ratio           REAL,
  ip_raw                TEXT,
  ip_subnet             TEXT,
  ip_16_subnet          TEXT,
  raw_signals           TEXT NOT NULL,
  raw_headers           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_visits_browser ON visits(browser_id);
CREATE INDEX IF NOT EXISTS idx_visits_seen    ON visits(seen_at);
"""

_conn = None


def get_conn():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _conn.commit()
    return _conn


def fetch_candidates(features, lookback_days=90):
    conn = get_conn()
    cutoff = int(time.time()) - lookback_days * 86400
    rows = conn.execute(
        """
        SELECT * FROM browser_profiles
         WHERE last_seen_at > ?
           AND (ja4 = ? OR webgl_renderer = ? OR font_hash = ? OR voice_hash = ?)
        """,
        (
            cutoff,
            features.get("ja4"),
            features.get("webgl_renderer"),
            features.get("font_hash"),
            features.get("voice_hash"),
        ),
    ).fetchall()
    return [dict(r) for r in rows]


def latest_visit(browser_id):
    row = get_conn().execute(
        "SELECT * FROM visits WHERE browser_id = ? ORDER BY visit_id DESC LIMIT 1",
        (browser_id,),
    ).fetchone()
    return dict(row) if row else None


def insert_visit(browser_id, features, match_score, is_new, raw_signals, raw_headers):
    conn = get_conn()
    cur = conn.execute(
        """
        INSERT INTO visits (
          browser_id, seen_at, match_score, is_new_browser,
          ja4, ja3_hash, h2fp,
          ua_family, ua_major, platform, vendor,
          webgl_renderer, webgl_vendor, webgl_render, webgl_ext_hash, webgl_caps_hash,
          font_hash, voice_hash, voice_count,
          audio_hash, css_supports_hash, constructor_count, event_handler_count,
          intl_hash, timezone, timezone_offset, language,
          max_touch_bucket, cookie_enabled, reduced_motion,
          color_depth, pixel_ratio,
          ip_raw, ip_subnet, ip_16_subnet,
          raw_signals, raw_headers
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            browser_id, int(time.time()), match_score, 1 if is_new else 0,
            features.get("ja4"), features.get("ja3_hash"), features.get("h2fp"),
            features.get("ua_family"), features.get("ua_major"),
            features.get("platform"), features.get("vendor"),
            features.get("webgl_renderer"), features.get("webgl_vendor"),
            features.get("webgl_render"), features.get("webgl_ext_hash"),
            features.get("webgl_caps_hash"),
            features.get("font_hash"), features.get("voice_hash"),
            features.get("voice_count"),
            features.get("audio_hash"), features.get("css_supports_hash"),
            features.get("constructor_count"), features.get("event_handler_count"),
            features.get("intl_hash"), features.get("timezone"),
            features.get("timezone_offset"), features.get("language"),
            features.get("max_touch_bucket"),
            1 if features.get("cookie_enabled") else 0,
            1 if features.get("reduced_motion") else 0,
            features.get("color_depth"), features.get("pixel_ratio"),
            features.get("ip_raw"), features.get("ip_subnet"),
            features.get("ip_16_subnet"),
            json.dumps(raw_signals), json.dumps(raw_headers),
        ),
    )
    conn.commit()
    return cur.lastrowid


def create_profile(browser_id, features, score):
    conn = get_conn()
    now = int(time.time())
    stable = {
        "ja4_modes":   [features["ja4"]]            if features.get("ja4") else [],
        "h2_modes":    [features["h2fp"]]           if features.get("h2fp") else [],
        "webgl_modes": [features["webgl_renderer"]] if features.get("webgl_renderer") else [],
        "font_modes":  [features["font_hash"]]      if features.get("font_hash") else [],
        "voice_modes": [features["voice_hash"]]     if features.get("voice_hash") else [],
    }
    semi = {
        "ua_major_history": [features["ua_major"]] if features.get("ua_major") else [],
        "timezones":        [features["timezone"]] if features.get("timezone") else [],
        "languages":        [features["language"]] if features.get("language") else [],
    }
    network = {
        "recent_ip_subnets": [features["ip_subnet"]]    if features.get("ip_subnet") else [],
        "recent_ip_16":      [features["ip_16_subnet"]] if features.get("ip_16_subnet") else [],
    }
    conn.execute(
        """
        INSERT INTO browser_profiles (
          browser_id, first_seen_at, last_seen_at, visit_count, current_confidence,
          ja4, webgl_renderer, font_hash, voice_hash,
          stable_profile, semi_stable_profile, network_profile
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            browser_id, now, now, 1, score,
            features.get("ja4"), features.get("webgl_renderer"),
            features.get("font_hash"), features.get("voice_hash"),
            json.dumps(stable), json.dumps(semi), json.dumps(network),
        ),
    )
    conn.commit()


def update_profile(browser_id, features, score):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM browser_profiles WHERE browser_id = ?", (browser_id,)
    ).fetchone()
    if not row:
        return
    stable  = json.loads(row["stable_profile"])
    semi    = json.loads(row["semi_stable_profile"])
    network = json.loads(row["network_profile"])

    def push(lst, val, max_len=10):
        if val is None or val == "":
            return
        if val in lst:
            lst.remove(val)
        lst.append(val)
        while len(lst) > max_len:
            lst.pop(0)

    push(stable["ja4_modes"],   features.get("ja4"))
    push(stable["h2_modes"],    features.get("h2fp"))
    push(stable["webgl_modes"], features.get("webgl_renderer"))
    push(stable["font_modes"],  features.get("font_hash"))
    push(stable["voice_modes"], features.get("voice_hash"))
    push(semi["ua_major_history"], features.get("ua_major"))
    push(semi["timezones"],        features.get("timezone"))
    push(semi["languages"],        features.get("language"))
    push(network["recent_ip_subnets"], features.get("ip_subnet"))
    push(network["recent_ip_16"],      features.get("ip_16_subnet"))

    old_conf = row["current_confidence"] or 0.0
    new_conf = 0.7 * old_conf + 0.3 * score

    conn.execute(
        """
        UPDATE browser_profiles SET
          last_seen_at        = ?,
          visit_count         = visit_count + 1,
          current_confidence  = ?,
          ja4                 = COALESCE(?, ja4),
          webgl_renderer      = COALESCE(?, webgl_renderer),
          font_hash           = COALESCE(?, font_hash),
          voice_hash          = COALESCE(?, voice_hash),
          stable_profile      = ?,
          semi_stable_profile = ?,
          network_profile     = ?
        WHERE browser_id = ?
        """,
        (
            int(time.time()), new_conf,
            features.get("ja4"), features.get("webgl_renderer"),
            features.get("font_hash"), features.get("voice_hash"),
            json.dumps(stable), json.dumps(semi), json.dumps(network),
            browser_id,
        ),
    )
    conn.commit()
