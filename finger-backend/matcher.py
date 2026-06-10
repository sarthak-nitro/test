import hashlib
import re
import time
import secrets
import logging

import db

log = logging.getLogger("finger-backend.matcher")


# ----------------------------- Normalization -----------------------------

def _sha1(s):
    return hashlib.sha1((s or "").encode("utf-8", errors="ignore")).hexdigest()


def _sorted_csv_hash(csv):
    if not csv:
        return None
    items = sorted(x.strip() for x in csv.split(",") if x.strip())
    return _sha1("|".join(items))


def _csv_set(csv):
    if not csv:
        return set()
    return {x.strip() for x in csv.split(",") if x.strip()}


def parse_ua(ua):
    if not ua:
        return None, None
    for token, name in (
        ("Edg", "Edge"),
        ("OPR", "Opera"),
        ("Firefox", "Firefox"),
        ("Chrome", "Chrome"),
        ("Safari", "Safari"),
    ):
        m = re.search(rf"{token}[/\s](\d+)", ua)
        if m:
            return name, int(m.group(1))
    return None, None


def ip_subnets(ip):
    if not ip:
        return None, None
    if ":" in ip:
        parts = ip.split(":")
        s48 = ":".join(parts[:3]) + "::/48"
        s32 = ":".join(parts[:2]) + "::/32"
        return s48, s32
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".0/24", ".".join(parts[:2]) + ".0.0/16"
    return None, None


def touch_bucket(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return None
    if n == 0:
        return "0"
    if n <= 4:
        return "1-4"
    return "5+"


def webgl_caps_hash(s):
    parts = [
        s.get("WebGL Max Texture Size"),
        s.get("WebGL Max Renderbuffer"),
        s.get("WebGL Max Viewport"),
        s.get("WebGL Max Vertex Attribs"),
        s.get("WebGL Max Vertex Uniforms"),
        s.get("WebGL Max Fragment Uniforms"),
        s.get("WebGL Max Combined Textures"),
    ]
    return _sha1("|".join(str(p) for p in parts))


def normalize(signals, headers, ip):
    ua = signals.get("User-Agent") or headers.get("user-agent") or headers.get("User-Agent")
    ua_family, ua_major = parse_ua(ua)
    sub24, sub16 = ip_subnets(ip)

    def h(key):
        return headers.get(key) or headers.get(key.lower())

    return {
        # network stack
        "ja4":      h("X-JA4"),
        "ja3_hash": h("X-JA3-Hash"),
        "h2fp":     h("X-H2FP"),
        # gpu
        "webgl_renderer": (signals.get("WebGL Renderer") or "").strip().lower() or None,
        "webgl_vendor":   (signals.get("WebGL Vendor") or "").strip().lower() or None,
        "webgl_render":   signals.get("WebGL Render"),
        "webgl_ext_hash": _sorted_csv_hash(signals.get("WebGL Extensions")),
        "webgl_caps_hash": webgl_caps_hash(signals),
        # device sets
        "font_hash":  _sorted_csv_hash(signals.get("Detected Fonts")),
        "voice_hash": _sorted_csv_hash(signals.get("Speech Voices")),
        "voice_count": signals.get("Speech Voices Count"),
        # browser version
        "ua_family": ua_family,
        "ua_major":  ua_major,
        "css_supports_hash":   _sha1(signals.get("CSS Supports") or ""),
        "constructor_count":   signals.get("Constructor Count"),
        "event_handler_count": signals.get("Event Handler Count"),
        # device/os
        "platform":        signals.get("Platform"),
        "vendor":          signals.get("Vendor"),
        "timezone":        signals.get("Timezone"),
        "timezone_offset": signals.get("Timezone Offset"),
        "language":        signals.get("Language"),
        "intl_hash":       _sha1(signals.get("Intl Fingerprint") or ""),
        # capability flags
        "max_touch_bucket": touch_bucket(signals.get("Max Touch Points")),
        "cookie_enabled":   signals.get("Cookie Enabled"),
        "reduced_motion":   signals.get("Reduced Motion"),
        "color_depth":      signals.get("Color Depth"),
        "pixel_ratio":      round(float(signals.get("Pixel Ratio") or 0), 1) or None,
        # noisy
        "audio_hash":  signals.get("Audio"),
        "canvas_hash": signals.get("Canvas"),
        # network context
        "ip_raw":       ip,
        "ip_subnet":    sub24,
        "ip_16_subnet": sub16,
        # raw sets used only during scoring, not persisted
        "_font_set":  _csv_set(signals.get("Detected Fonts")),
        "_voice_set": _csv_set(signals.get("Speech Voices")),
    }


# ----------------------------- Scoring -----------------------------

WEIGHTS = {
    "ja4":             0.08,
    "h2fp":            0.05,
    "webgl_renderer":  0.08,
    "webgl_vendor":    0.03,
    "webgl_render":    0.10,
    "webgl_caps_hash": 0.03,
    "webgl_ext_hash":  0.02,
    "font_jaccard":    0.08,
    "voice_jaccard":   0.06,
    "voice_count":     0.02,
    "ua":              0.04,
    "version_combo":   0.03,
    "platform":        0.02,
    "vendor":          0.01,
    "timezone":        0.02,
    "language":        0.01,
    "intl":            0.02,
    "touch":           0.01,
    "cookie":          0.01,
    "motion":          0.01,
    "color_depth":     0.005,
    "pixel_ratio":     0.005,
    "audio":           0.10,
    "canvas":          0.08,
    "ip_24":           0.05,
    "ip_16":           0.03,
}


def _eq(a, b):
    return 1.0 if a is not None and a == b else 0.0


def jaccard(a, b):
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def ua_score(new_fam, new_major, old_fam, old_major):
    if not new_fam or not old_fam or new_fam != old_fam:
        return 0.0
    if new_major is None or old_major is None:
        return 0.4
    if new_major == old_major:
        return 1.0
    if abs(new_major - old_major) <= 1:
        return 0.7
    return 0.4


VENDOR_PATTERN = re.compile(
    r"\b(apple|nvidia|amd|intel|arm|qualcomm|imagination|mali|adreno)\b"
)


def vendor_family(s):
    if not s:
        return None
    m = VENDOR_PATTERN.search(s.lower())
    return m.group(1) if m else None


def time_decay(last_seen_at):
    days = (time.time() - last_seen_at) / 86400
    if days < 7:
        return 1.0
    if days < 30:
        return 0.85
    if days < 90:
        return 0.70
    return 0.50


def contradiction_penalty(features, latest):
    penalty = 0.0
    if not latest:
        return penalty

    new_vf = vendor_family(features.get("webgl_renderer"))
    old_vf = vendor_family(latest.get("webgl_renderer"))
    if new_vf and old_vf and new_vf != old_vf:
        penalty -= 0.30

    new_ua = features.get("ua_family")
    old_ua = latest.get("ua_family")
    if new_ua and old_ua and new_ua != old_ua:
        penalty -= 0.40

    new_plat = (features.get("platform") or "").lower()
    old_plat = (latest.get("platform") or "").lower()
    if new_plat and old_plat and new_plat != old_plat:
        penalty -= 0.30

    new_canvas = features.get("canvas_hash")
    old_canvas = latest.get("canvas_hash")
    if new_canvas and old_canvas and new_canvas != old_canvas:
        penalty -= 0.15

    return penalty


def score_profile(features, profile):
    stable  = profile["stable_profile"]
    network = profile["network_profile"]
    latest  = db.latest_visit(profile["browser_id"])

    w = WEIGHTS
    s = 0.0

    s += w["ja4"]  * (1.0 if features.get("ja4")  in stable.get("ja4_modes", [])  else 0.0)
    s += w["h2fp"] * (1.0 if features.get("h2fp") in stable.get("h2_modes",  [])  else 0.0)

    f_webgl = features.get("webgl_renderer")
    p_webgl_modes = stable.get("webgl_modes", [])
    if f_webgl and f_webgl in p_webgl_modes:
        s += w["webgl_renderer"]
    elif f_webgl:
        nvf = vendor_family(f_webgl)
        if nvf and any(vendor_family(x) == nvf for x in p_webgl_modes):
            s += w["webgl_renderer"] * 0.4

    if latest:
        s += w["webgl_vendor"]    * _eq(features.get("webgl_vendor"),    latest["webgl_vendor"])
        s += w["webgl_render"]    * _eq(features.get("webgl_render"),    latest["webgl_render"])
        s += w["webgl_caps_hash"] * _eq(features.get("webgl_caps_hash"), latest["webgl_caps_hash"])
        s += w["webgl_ext_hash"]  * _eq(features.get("webgl_ext_hash"),  latest["webgl_ext_hash"])

        latest_signals = latest["raw_signals"] or {}
        s += w["font_jaccard"]  * jaccard(features.get("_font_set", set()),
                                          _csv_set(latest_signals.get("Detected Fonts")))
        s += w["voice_jaccard"] * jaccard(features.get("_voice_set", set()),
                                          _csv_set(latest_signals.get("Speech Voices")))
        s += w["voice_count"]   * _eq(features.get("voice_count"), latest["voice_count"])

        version_matches = sum(
            1 for a, b in zip(
                (features.get("css_supports_hash"),
                 features.get("constructor_count"),
                 features.get("event_handler_count")),
                (latest["css_supports_hash"],
                 latest["constructor_count"],
                 latest["event_handler_count"]),
            )
            if a is not None and a == b
        )
        s += w["version_combo"] * (version_matches / 3.0)

        s += w["ua"] * ua_score(
            features.get("ua_family"), features.get("ua_major"),
            latest["ua_family"], latest["ua_major"],
        )

        s += w["platform"]    * _eq(features.get("platform"),    latest["platform"])
        s += w["vendor"]      * _eq(features.get("vendor"),      latest["vendor"])
        s += w["timezone"]    * _eq(features.get("timezone"),    latest["timezone"])
        s += w["language"]    * _eq(features.get("language"),    latest["language"])
        s += w["intl"]        * _eq(features.get("intl_hash"),   latest["intl_hash"])
        s += w["touch"]       * _eq(features.get("max_touch_bucket"), latest["max_touch_bucket"])
        s += w["cookie"]      * _eq(1 if features.get("cookie_enabled") else 0, latest["cookie_enabled"])
        s += w["motion"]      * _eq(1 if features.get("reduced_motion") else 0, latest["reduced_motion"])
        s += w["color_depth"] * _eq(features.get("color_depth"), latest["color_depth"])
        s += w["pixel_ratio"] * _eq(features.get("pixel_ratio"), latest["pixel_ratio"])
        s += w["audio"]       * _eq(features.get("audio_hash"),  latest["audio_hash"])
        s += w["canvas"]      * _eq(features.get("canvas_hash"), latest.get("canvas_hash"))

    s += w["ip_24"] * (1.0 if features.get("ip_subnet")    in network.get("recent_ip_subnets", []) else 0.0)
    s += w["ip_16"] * (1.0 if features.get("ip_16_subnet") in network.get("recent_ip_16", [])      else 0.0)

    s *= time_decay(profile["last_seen_at"])
    s += contradiction_penalty(features, latest)

    return max(0.0, min(1.0, s))


# ----------------------------- Match entry point -----------------------------

THRESHOLD_HIGH = 0.93
THRESHOLD_GRAY = 0.75


def _gray_zone_anchor_ok(features, profile):
    network = profile["network_profile"]
    stable  = profile["stable_profile"]
    if features.get("ip_subnet") and features["ip_subnet"] in network.get("recent_ip_subnets", []):
        return True
    if features.get("font_hash") and features["font_hash"] in stable.get("font_modes", []):
        return True
    return False


def match_or_create(signals, headers, ip):
    features = normalize(signals, headers, ip)
    log.debug(
        "normalized: ja4=%s h2fp=%s ua=%s/%s platform=%s webgl=%s font_hash=%s voice_hash=%s ip=%s",
        features.get("ja4"), features.get("h2fp"),
        features.get("ua_family"), features.get("ua_major"),
        features.get("platform"), (features.get("webgl_renderer") or "")[:60],
        features.get("font_hash"), features.get("voice_hash"),
        features.get("ip_subnet"),
    )

    candidates = db.fetch_candidates(features)
    log.info("candidates=%d for ja4=%s webgl=%s font=%s voice=%s",
             len(candidates), features.get("ja4"),
             (features.get("webgl_renderer") or "")[:40],
             features.get("font_hash"), features.get("voice_hash"))

    best = None
    best_score = 0.0
    for c in candidates:
        s = score_profile(features, c)
        log.debug("candidate=%s score=%.3f visits=%s last_seen=%s",
                  c["browser_id"], s, c.get("visit_count"), c.get("last_seen_at"))
        if s > best_score:
            best_score = s
            best = c

    is_new = False
    matched_id = None

    if best and best_score >= THRESHOLD_HIGH:
        browser_id = best["browser_id"]
        matched_id = browser_id
        decision = "match"
        db.update_profile(browser_id, features, best_score)
    elif best and best_score >= THRESHOLD_GRAY and _gray_zone_anchor_ok(features, best):
        browser_id = best["browser_id"]
        matched_id = browser_id
        decision = "gray-match"
        db.update_profile(browser_id, features, best_score)
    else:
        browser_id = "br_" + secrets.token_hex(8)
        db.create_profile(browser_id, features, 1.0 if not best else best_score)
        is_new = True
        decision = "new"

    visit_id = db.insert_visit(browser_id, features, best_score, is_new, signals, headers)

    log.info(
        "decision=%s browser_id=%s score=%.3f candidates=%d ip=%s ja4=%s webgl=%s",
        decision, browser_id, best_score, len(candidates),
        features.get("ip_subnet"), features.get("ja4"),
        (features.get("webgl_renderer") or "")[:40],
    )

    return {
        "browser_id":       browser_id,
        "is_new_browser":   is_new,
        "match_score":      round(best_score, 4),
        "matched_against":  matched_id,
        "candidate_count":  len(candidates),
        "visit_id":         visit_id,
    }
