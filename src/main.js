import './style.css';
import { cyrb53, getCanvasFingerprint, getAudioFingerprint, getWebGLFingerprint, getDetectedFonts, getWebGLRenderFingerprint, getConstructorCount, getCSSSupports, getEventHandlerCount, getIntlFingerprint } from './fingerprint.js';

document.querySelector('#app').innerHTML = `
    <h1>Custom Browser Fingerprint</h1>
    <div id="signals"></div>
    <div id="final">Collecting signals...</div>
`;

async function collectFingerprint() {
    const signals = {};

    // Navigator properties
    signals['User-Agent'] = navigator.userAgent;
    signals['Platform'] = navigator.platform;
    signals['Language'] = navigator.language;
    // signals['CPU Cores'] = navigator.hardwareConcurrency;
    // signals['Device Memory'] = navigator.deviceMemory || 'n/a';
    signals['Max Touch Points'] = navigator.maxTouchPoints;
    signals['Do Not Track'] = navigator.doNotTrack || 'n/a';
    // signals['Cookie Enabled'] = navigator.cookieEnabled;
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

    // Speech Voices (different per OS version — very high entropy)
    const voices = await new Promise((resolve) => {
        const v = speechSynthesis.getVoices();
        if (v.length > 0) return resolve(v);
        speechSynthesis.onvoiceschanged = () => resolve(speechSynthesis.getVoices());
    });
    signals['Speech Voices'] = voices.map(v => v.name + ':' + v.lang).join(', ');
    signals['Speech Voices Count'] = voices.length;

    // Display signals
    const container = document.getElementById('signals');
    let rawString = '';

    for (const [label, value] of Object.entries(signals)) {
        const div = document.createElement('div');
        div.className = 'signal';
        div.innerHTML = `<span class="label">${label}:</span> <span class="value">${value}</span>`;
        container.appendChild(div);
        rawString += label + ':' + value + '|';
    }
    // console.log(rawString,"raw string");
    

    // Generate final hash
    const hash = cyrb53(rawString);
    document.getElementById('final').innerHTML =
        '&#x1f9ec; FINAL FINGERPRINT: <strong>' + hash + '</strong>';

    try {
        const response = await fetch("https://client-app.getnitro.co.in/collect");
        const data = await response.json();
        console.log('X-Entity-Session:', data['X-Entity-Session']);
        console.log('X-H2FP:', data['X-H2FP']);
        console.log('X-JA3:', data['X-JA3']);
        console.log('X-JA3-Hash:', data['X-JA3-Hash']);
        console.log('X-JA4:', data['X-JA4']);
        console.log('X-Real-IP:', data['X-Real-IP']);
        console.log('X-Request-ID:', data['X-Request-ID']);
    } catch (e) {
        console.log('API blocked by CORS', e);
    }
    console.log('All signals:', signals);
    console.log('Final fingerprint:', hash);
}

collectFingerprint();
