import os
import time
import logging

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

log = logging.getLogger("finger-backend.db")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://fingerapp:StrongPassword123!@127.0.0.1/fingerprints",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS browser_profiles (
  browser_id            TEXT PRIMARY KEY,
  first_seen_at         BIGINT NOT NULL,
  last_seen_at          BIGINT NOT NULL,
  visit_count           INTEGER NOT NULL DEFAULT 1,
  current_confidence    DOUBLE PRECISION NOT NULL,
  ja4                   TEXT,
  webgl_renderer        TEXT,
  font_hash             TEXT,
  voice_hash            TEXT,
  stable_profile        JSONB NOT NULL,
  semi_stable_profile   JSONB NOT NULL,
  network_profile       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_prof_ja4       ON browser_profiles(ja4);
CREATE INDEX IF NOT EXISTS idx_prof_webgl     ON browser_profiles(webgl_renderer);
CREATE INDEX IF NOT EXISTS idx_prof_font      ON browser_profiles(font_hash);
CREATE INDEX IF NOT EXISTS idx_prof_voice     ON browser_profiles(voice_hash);
CREATE INDEX IF NOT EXISTS idx_prof_last_seen ON browser_profiles(last_seen_at);

CREATE TABLE IF NOT EXISTS visits (
  visit_id              BIGSERIAL PRIMARY KEY,
  browser_id            TEXT NOT NULL REFERENCES browser_profiles(browser_id),
  seen_at               BIGINT NOT NULL,
  match_score           DOUBLE PRECISION,
  is_new_browser        SMALLINT NOT NULL,
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
  canvas_hash           TEXT,
  css_supports_hash     TEXT,
  constructor_count     INTEGER,
  event_handler_count   INTEGER,
  intl_hash             TEXT,
  timezone              TEXT,
  timezone_offset       INTEGER,
  language              TEXT,
  max_touch_bucket      TEXT,
  cookie_enabled        SMALLINT,
  reduced_motion        SMALLINT,
  color_depth           INTEGER,
  pixel_ratio           DOUBLE PRECISION,
  ip_raw                TEXT,
  ip_subnet             TEXT,
  ip_16_subnet          TEXT,
  raw_signals           JSONB NOT NULL,
  raw_headers           JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visits_browser ON visits(browser_id);
CREATE INDEX IF NOT EXISTS idx_visits_seen    ON visits(seen_at);
"""

_pool = None


def _pool_handle():
    global _pool
    if _pool is None:
        log.info("opening connection pool to %s", DATABASE_URL.split("@", 1)[-1])
        _pool = ConnectionPool(
            DATABASE_URL,
            min_size=1,
            max_size=8,
            kwargs={"row_factory": dict_row, "autocommit": True},
        )
        with _pool.connection() as conn:
            conn.execute(SCHEMA)
        log.info("schema bootstrap complete")
    return _pool


def fetch_candidates(features, lookback_days=90):
    cutoff = int(time.time()) - lookback_days * 86400
    with _pool_handle().connection() as conn:
        return conn.execute(
            """
            SELECT * FROM browser_profiles
             WHERE last_seen_at > %s
               AND (ja4 = %s OR webgl_renderer = %s OR font_hash = %s OR voice_hash = %s)
            """,
            (
                cutoff,
                features.get("ja4"),
                features.get("webgl_renderer"),
                features.get("font_hash"),
                features.get("voice_hash"),
            ),
        ).fetchall()


def latest_visit(browser_id):
    with _pool_handle().connection() as conn:
        return conn.execute(
            "SELECT * FROM visits WHERE browser_id = %s ORDER BY visit_id DESC LIMIT 1",
            (browser_id,),
        ).fetchone()


def insert_visit(browser_id, features, match_score, is_new, raw_signals, raw_headers):
    with _pool_handle().connection() as conn:
        row = conn.execute(
            """
            INSERT INTO visits (
              browser_id, seen_at, match_score, is_new_browser,
              ja4, ja3_hash, h2fp,
              ua_family, ua_major, platform, vendor,
              webgl_renderer, webgl_vendor, webgl_render, webgl_ext_hash, webgl_caps_hash,
              font_hash, voice_hash, voice_count,
              audio_hash, canvas_hash, css_supports_hash, constructor_count, event_handler_count,
              intl_hash, timezone, timezone_offset, language,
              max_touch_bucket, cookie_enabled, reduced_motion,
              color_depth, pixel_ratio,
              ip_raw, ip_subnet, ip_16_subnet,
              raw_signals, raw_headers
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING visit_id
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
                features.get("audio_hash"), features.get("canvas_hash"),
                features.get("css_supports_hash"),
                features.get("constructor_count"), features.get("event_handler_count"),
                features.get("intl_hash"), features.get("timezone"),
                features.get("timezone_offset"), features.get("language"),
                features.get("max_touch_bucket"),
                1 if features.get("cookie_enabled") else 0,
                1 if features.get("reduced_motion") else 0,
                features.get("color_depth"), features.get("pixel_ratio"),
                features.get("ip_raw"), features.get("ip_subnet"),
                features.get("ip_16_subnet"),
                Jsonb(raw_signals), Jsonb(raw_headers),
            ),
        ).fetchone()
        return row["visit_id"]


def create_profile(browser_id, features, score):
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
    with _pool_handle().connection() as conn:
        conn.execute(
            """
            INSERT INTO browser_profiles (
              browser_id, first_seen_at, last_seen_at, visit_count, current_confidence,
              ja4, webgl_renderer, font_hash, voice_hash,
              stable_profile, semi_stable_profile, network_profile
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                browser_id, now, now, 1, score,
                features.get("ja4"), features.get("webgl_renderer"),
                features.get("font_hash"), features.get("voice_hash"),
                Jsonb(stable), Jsonb(semi), Jsonb(network),
            ),
        )


def update_profile(browser_id, features, score):
    pool = _pool_handle()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT * FROM browser_profiles WHERE browser_id = %s",
            (browser_id,),
        ).fetchone()
    if not row:
        return

    stable  = row["stable_profile"]
    semi    = row["semi_stable_profile"]
    network = row["network_profile"]

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

    with pool.connection() as conn:
        conn.execute(
            """
            UPDATE browser_profiles SET
              last_seen_at        = %s,
              visit_count         = visit_count + 1,
              current_confidence  = %s,
              ja4                 = COALESCE(%s, ja4),
              webgl_renderer      = COALESCE(%s, webgl_renderer),
              font_hash           = COALESCE(%s, font_hash),
              voice_hash          = COALESCE(%s, voice_hash),
              stable_profile      = %s,
              semi_stable_profile = %s,
              network_profile     = %s
            WHERE browser_id = %s
            """,
            (
                int(time.time()), new_conf,
                features.get("ja4"), features.get("webgl_renderer"),
                features.get("font_hash"), features.get("voice_hash"),
                Jsonb(stable), Jsonb(semi), Jsonb(network),
                browser_id,
            ),
        )
