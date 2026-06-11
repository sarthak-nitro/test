import { cyrb53, getCanvasFingerprint, getAudioFingerprint, getWebGLFingerprint, getDetectedFonts, getWebGLRenderFingerprint, getConstructorCount, getCSSSupports, getEventHandlerCount, getIntlFingerprint } from './fingerprint.js';

export async function getFingerprint() {
    const signals = {};

    // Navigator properties
    signals['User-Agent'] = navigator.userAgent;
    signals['Platform'] = navigator.platform;
    signals['Language'] = navigator.language;
    // signals['CPU Cores'] = navigator.hardwareConcurrency;
    // signals['Device Memory'] = navigator.deviceMemory || 'n/a';
    signals['Max Touch Points'] = navigator.maxTouchPoints;
    // signals['Do Not Track'] = navigator.doNotTrack || 'n/a';
    signals['Cookie Enabled'] = navigator.cookieEnabled;
    signals['Vendor'] = navigator.vendor || 'n/a';
    signals['Reduced Motion'] = matchMedia('(prefers-reduced-motion: reduce)').matches;

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
        const result = await getFingerprint();

        // visitor_id: wrap in own try/catch — localStorage throws in some private/strict modes.
        // Falling back to an ephemeral id keeps the POST alive.
        let visitorId = null;
        try {
            visitorId = localStorage.getItem('visitor_id');
            if (!visitorId) {
                visitorId = Date.now().toString(36) + Math.random().toString(36).substring(2, 12);
                localStorage.setItem('visitor_id', visitorId);
            }
        } catch (e) {
            visitorId = Date.now().toString(36) + Math.random().toString(36).substring(2, 12);
        }

        // Fingerprint Pro (commercial baseline for benchmarking our matcher).
        // Wrapped in try/catch — if blocked by ETP/ad-blocker, our pipeline still runs.
        let fpProVisitorId = null, fpProRequestId = null;
        try {
            const Fingerprint = await import('https://fpjscdn.net/v4/Zkmx5qbFdAbNSqfyjbLI');
            const fp = await Fingerprint.start({ region: 'ap' });
            const fpResult = await fp.get();
            fpProVisitorId = fpResult.visitorId || null;
            fpProRequestId = fpResult.requestId || null;
        } catch (e) {
            try { console.warn('[Fingerprint Pro skipped]', e); } catch (_) { }
        }

        const url = "https://client-app.getnitro.co.in/collect";
        const payload = JSON.stringify({
            visitor_id: visitorId,
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

        // Primary: fetch with keepalive + text/plain (simple CORS, no preflight).
        // Reads the response so we can log browser_id / score and expose them via window.
        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                body: payload
            });
            const data = await res.json();
            if (data && data.browser_id) {
                const info = {
                    browserId:  data.browser_id,
                    matchScore: data.match_score,
                    isNew:      data.is_new_browser,
                    visitId:    data.visit_id
                };
                window.NitroFingerprint = Object.assign(window.NitroFingerprint || {}, info);
                try { console.log(); } catch (_) { }
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
