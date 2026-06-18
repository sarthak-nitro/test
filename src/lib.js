import { cyrb53, getCanvasFingerprint, getAudioFingerprint, getWebGLFingerprint, getDetectedFonts, getWebGLRenderFingerprint, getConstructorCount, getCSSSupports, getEventHandlerCount, getIntlFingerprint } from './fingerprint.js';

export async function getFingerprint() {
    const signals = {};

    // Navigator properties
    signals['User-Agent'] = navigator.userAgent;
    signals['Platform'] = navigator.platform;
    signals['Language'] = navigator.language;
    signals['Max Touch Points'] = navigator.maxTouchPoints;
    // signals['Do Not Track'] = navigator.doNotTrack || 'n/a';
    signals['Cookie Enabled'] = navigator.cookieEnabled;
    signals['Vendor'] = navigator.vendor || 'n/a';
    signals['Reduced Motion'] = matchMedia('(prefers-reduced-motion: reduce)').matches;
    signals['Prefers Color Scheme Dark'] = matchMedia('(prefers-color-scheme: dark)').matches;
    signals['Prefers Contrast More'] = matchMedia('(prefers-contrast: more)').matches;
    signals['Forced Colors'] = matchMedia('(forced-colors: active)').matches;
    signals['Dynamic Range High'] = matchMedia('(dynamic-range: high)').matches;
    signals['Color Gamut P3'] = matchMedia('(color-gamut: p3)').matches;
    signals['Color Gamut Rec2020'] = matchMedia('(color-gamut: rec2020)').matches;
    signals['Pointer Coarse'] = matchMedia('(pointer: coarse)').matches;
    signals['Hover Hover'] = matchMedia('(hover: hover)').matches;
    signals['Display Mode Standalone'] = matchMedia('(display-mode: standalone)').matches;

    // Screen
    signals['Color Depth'] = screen.colorDepth;
    signals['Pixel Ratio'] = window.devicePixelRatio;

    // Timezone
    signals['Timezone'] = Intl.DateTimeFormat().resolvedOptions().timeZone;
    signals['Timezone Offset'] = new Date().getTimezoneOffset();

    // WebGL
    const webgl = getWebGLFingerprint();
    signals['WebGL Vendor'] = webgl.vendor;
    signals['WebGL Renderer'] = webgl.renderer;
    signals['WebGL Extensions'] = webgl.extensions;
    signals['WebGL Max Texture Size'] = webgl.maxTextureSize;
    signals['WebGL Max Renderbuffer'] = webgl.maxRenderbufferSize;
    signals['WebGL Max Viewport'] = webgl.maxViewportDims;
    signals['WebGL Max Vertex Attribs'] = webgl.maxVertexAttribs;
    signals['WebGL Max Vertex Uniforms'] = webgl.maxVertexUniformVectors;
    signals['WebGL Max Fragment Uniforms'] = webgl.maxFragmentUniformVectors;
    signals['WebGL Max Combined Textures'] = webgl.maxCombinedTextureUnits;

    // Fonts
    signals['Detected Fonts'] = getDetectedFonts().join(', ');

    // Canvas (GPU pixel-level fingerprint)
    signals['Canvas'] = getCanvasFingerprint();

    // Audio
    signals['Audio'] = await getAudioFingerprint();

    // Automation flag — false in real browsers, true under Selenium/Puppeteer/Playwright
    signals['Webdriver'] = !!navigator.webdriver;

    // AudioContext.baseLatency — distinct per browser/audio path (Firefox returns 0)
    signals['Audio Latency'] = (() => {
        try {
            const AC = window.AudioContext || window['webkitAudioContext'];
            const c = new AC();
            const v = c.baseLatency;
            c.close();
            return v;
        } catch (e) { return null; }
    })();

    // WebGL Render (GPU pixel-level fingerprint)
    signals['WebGL Render'] = getWebGLRenderFingerprint();

    // Version signals
    signals['Constructor Count'] = getConstructorCount();
    signals['CSS Supports'] = getCSSSupports();
    signals['Event Handler Count'] = getEventHandlerCount();

    // Intl (per-device OS locale)
    signals['Intl Fingerprint'] = getIntlFingerprint();

    // Speech Voices
    // Some Firefox configs return [] and never fire onvoiceschanged — add 1.5s timeout
    // so the script never hangs.
    const voices = await new Promise((resolve) => {
        let done = false;
        const finish = (v) => { if (!done) { done = true; resolve(v || []); } };
        try {
            const v = speechSynthesis.getVoices();
            if (v && v.length > 0) return finish(v);
            speechSynthesis.onvoiceschanged = () => finish(speechSynthesis.getVoices());
        } catch (e) { /* speechSynthesis unavailable */ }
        setTimeout(() => finish(speechSynthesis.getVoices && speechSynthesis.getVoices()), 1500);
    });
    signals['Speech Voices'] = voices.map(v => v.name + ':' + v.lang).join(', ');
    signals['Speech Voices Count'] = voices.length;

    // Build hash from all signals
    let rawString = '';
    for (const [label, value] of Object.entries(signals)) {
        rawString += label + ':' + value + '|';
    }

    const fingerprint = cyrb53(rawString).toString();

    let entitySession = null;
    let h2fp = null;
    let ja3 = null;
    let ja3Hash = null;
    let ja4 = null;
    let realIP = null;
    let requestID = null;

    try {
        const response = await fetch("https://client-app.getnitro.co.in/collect");
        const data = await response.json();
        entitySession = data['X-Entity-Session'];
        h2fp = data['X-H2FP'];
        ja3 = data['X-JA3'];
        ja3Hash = data['X-JA3-Hash'];
        ja4 = data['X-JA4'];
        realIP = data['X-Real-IP'];
        requestID = data['X-Request-ID'];
    } catch (e) {}

    return {
        fingerprint,
        signals,
        entitySession,
        h2fp,
        ja3,
        ja3Hash,
        ja4,
        realIP,
        requestID
    };
}

// Auto-collect and send on load
(async function () {
    try {
        // Fast path: per-domain cache. If browser_id is already in localStorage,
        // skip fingerprinting AND skip the POST entirely.
        let cachedBrowserId = null;
        try {
            cachedBrowserId = localStorage.getItem('browser_id');
        } catch (e) { /* localStorage unavailable in private/strict modes */ }

        if (cachedBrowserId) {
            window.NitroFingerprint = Object.assign(window.NitroFingerprint || {}, {
                browserId: cachedBrowserId,
                fromCache: true,
            });
            return;
        }

        const result = await getFingerprint();

        // Fingerprint Pro (commercial baseline for benchmarking our matcher).
        // Wrapped in try/catch — if blocked by ETP/ad-blocker, our pipeline still runs.
        let fpProVisitorId = null, fpProRequestId = null;
        try {
            const Fingerprint = await import('https://client-app.getnitro.co.in/fpjs/script');
            const fp = await Fingerprint.start({ region: 'ap' });
            const fpResult = await fp.get();
            fpProVisitorId = (fpResult && (fpResult.visitor_id || fpResult.visitorId)) || null;
            fpProRequestId = (fpResult && (fpResult.event_id  || fpResult.requestId)) || null;
        } catch (e) {
            console.error('Fingerprint Pro failed');
            console.error(e);
            console.error(e && e.message);
            console.error(e && e.stack);
        }

        const url = "https://client-app.getnitro.co.in/collect";
        const payload = JSON.stringify({
            fingerprint: result.fingerprint,
            timestamp: Date.now(),
            url: window.location.href,
            hostname: window.location.hostname,
            path: window.location.pathname,
            referrer: document.referrer,
            signals: result.signals,
            entitySession: result.entitySession,
            h2fp: result.h2fp,
            ja3: result.ja3,
            ja3Hash: result.ja3Hash,
            ja4: result.ja4,
            realIP: result.realIP,
            requestID: result.requestID,
            fp_pro_visitor_id: fpProVisitorId,
            fp_pro_request_id: fpProRequestId
        });

        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                body: payload
            });
            const data = await res.json();
            if (data && data.browser_id) {
                try {
                    localStorage.setItem('browser_id', data.browser_id);
                } catch (e) { /* localStorage unavailable */ }

                const info = {
                    browserId:  data.browser_id,
                    matchScore: data.match_score,
                    isNew:      data.is_new_browser,
                    visitId:    data.visit_id,
                    fpProVisitorId: fpProVisitorId,
                    fpProRequestId: fpProRequestId,
                    fromCache:  false,
                };
                window.NitroFingerprint = Object.assign(window.NitroFingerprint || {}, info);
            }
        } catch (err) {
            console.error('Collect failed:', err);
        }
    } catch (e) {
        try { console.log('[NitroFingerprint]', e); } catch (_) { }
    }
})();

// Also export individual functions for advanced users
export { cyrb53, getCanvasFingerprint, getAudioFingerprint, getWebGLFingerprint, getDetectedFonts, getWebGLRenderFingerprint, getConstructorCount, getCSSSupports, getEventHandlerCount, getIntlFingerprint };
