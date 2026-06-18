// --- cyrb53 hash (fast, non-cryptographic 53-bit hash) ---
export function cyrb53(str, seed = 0) {
    let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
    for (let i = 0; i < str.length; i++) {
        let ch = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
    h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
    h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

// --- Canvas fingerprint (multi-sub-canvas + median-of-3) ---
// Returns "text:curves:gradient:shadow" — 4 sub-hashes joined.
// Each sub-canvas drawn 3x into offscreen contexts; modal value kept.
// Output stays short (~45 chars) so POST body stays small.

function _hashPixels(pixels) {
    let h = 0;
    for (let i = 0; i < pixels.length; i++) {
        h = ((h << 5) - h + (Math.round(pixels[i] / 4) * 4)) | 0;
    }
    return h.toString();
}

function _mode(arr) {
    const c = {};
    arr.forEach(v => c[v] = (c[v] || 0) + 1);
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0][0];
}

function _drawText(ctx, w, h) {
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = '#000';
    ctx.textBaseline = 'top';
    ctx.font = "16px 'Times New Roman', serif";
    ctx.fillText('AaBbCc 0123', 4, 4);
    ctx.font = "14px 'Helvetica Neue', sans-serif";
    ctx.fillText('μΩ∑π√≈', 4, 22);
}
function _drawCurves(ctx, w, h) {
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = '#000'; ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(10.5, 10.5);
    ctx.bezierCurveTo(60.5, 10.5, 60.5, 80.5, 10.5, 80.5);
    ctx.stroke();
    ctx.beginPath(); ctx.arc(100.5, 50.5, 30.5, 0, Math.PI * 2); ctx.stroke();
    ctx.beginPath(); ctx.arc(160.5, 50.5, 20.5, 0, Math.PI * 1.5); ctx.stroke();
}
function _drawGradient(ctx, w, h) {
    const g = ctx.createLinearGradient(0, 0, w, 0);
    g.addColorStop(0, '#ff0000');
    g.addColorStop(0.5, '#00ff00');
    g.addColorStop(1, '#0000ff');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);
}
function _drawShadow(ctx, w, h) {
    ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, h);
    ctx.shadowColor = 'rgba(0,0,255,0.6)';
    ctx.shadowBlur = 12;
    ctx.fillStyle = '#000';
    ctx.fillRect(30, 20, 40, 40);
    ctx.shadowBlur = 0;
    ctx.shadowColor = 'transparent';
}

function _subHash(draw, w, h) {
    try {
        const trials = [];
        for (let i = 0; i < 3; i++) {
            const c = document.createElement('canvas');
            c.width = w; c.height = h;
            const ctx = c.getContext('2d');
            draw(ctx, w, h);
            trials.push(_hashPixels(ctx.getImageData(0, 0, w, h).data));
        }
        return _mode(trials);
    } catch (e) {
        return 'err';
    }
}

export function getCanvasFingerprint() {
    try {
        return [
            _subHash(_drawText,     250, 40),
            _subHash(_drawCurves,   200, 100),
            _subHash(_drawGradient, 200, 40),
            _subHash(_drawShadow,   100, 80),
        ].join(':');
    } catch (e) {
        return 'canvas-not-supported';
    }
}

// --- Canvas raw pixel data ---
export function getCanvasRawData() {
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 50;
        const ctx = canvas.getContext('2d');

        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(0, 0, 200, 50);

        ctx.fillStyle = '#069';
        ctx.fillText('BrowserFingerprint!', 2, 15);

        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('CustomSignal123', 4, 30);

        ctx.beginPath();
        ctx.arc(50, 25, 10, 0, Math.PI * 2);
        ctx.fillStyle = '#ff0080';
        ctx.fill();

        // Get raw pixel data — array of [R, G, B, A, R, G, B, A, ...]
        const imageData = ctx.getImageData(0, 0, 200, 50);
        const pixels = imageData.data; // Uint8ClampedArray, length = 200*50*4 = 40000

        // Collect unique pixel values (RGBA as string)
        const uniquePixels = new Set();
        for (let i = 0; i < pixels.length; i += 4) {
            const r = pixels[i];
            const g = pixels[i + 1];
            const b = pixels[i + 2];
            const a = pixels[i + 3];
            uniquePixels.add(`${r},${g},${b},${a}`);
        }

        return {
            totalPixels: pixels.length / 4,
            uniqueColors: uniquePixels.size,
            uniqueList: [...uniquePixels],
            rawArray: pixels
        };
    } catch (e) {
        return null;
    }
}

// --- Audio fingerprint ---
export async function getAudioFingerprint() {
    try {
        const ctx = new OfflineAudioContext(1, 5000, 44100);
        const oscillator = ctx.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, ctx.currentTime);

        const compressor = ctx.createDynamicsCompressor();
        compressor.threshold.setValueAtTime(-50, ctx.currentTime);
        compressor.knee.setValueAtTime(40, ctx.currentTime);
        compressor.ratio.setValueAtTime(12, ctx.currentTime);
        compressor.attack.setValueAtTime(0, ctx.currentTime);
        compressor.release.setValueAtTime(0.25, ctx.currentTime);

        oscillator.connect(compressor);
        compressor.connect(ctx.destination);
        oscillator.start(0);

        const buffer = await ctx.startRendering();
        const data = buffer.getChannelData(0);
        let sum = 0;
        for (let i = 4500; i < 5000; i++) {
            sum += Math.abs(data[i]);
        }
        return Math.round(sum).toString();
    } catch (e) {
        return 'audio-not-supported';
    }
}

// --- WebGL fingerprint ---
export function getWebGLFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) {
            return { vendor: 'n/a', renderer: 'n/a', extensions: 'n/a', maxTextureSize: 'n/a', maxRenderbufferSize: 'n/a', maxViewportDims: 'n/a', maxVertexAttribs: 'n/a', maxVertexUniformVectors: 'n/a', maxFragmentUniformVectors: 'n/a', maxCombinedTextureUnits: 'n/a' };
        }
        // In Firefox strict / privacy.resistFingerprinting, the privileged extension is null.
        // Fall back to non-privileged getParameter so the fields still have *some* value
        // (generic "Mozilla" strings) rather than 'n/a' everywhere.
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const vendor = debugInfo
            ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
            : gl.getParameter(gl.VENDOR);
        const renderer = debugInfo
            ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
            : gl.getParameter(gl.RENDERER);
        return {
            vendor: vendor || 'n/a',
            renderer: renderer || 'n/a',
            extensions: (gl.getSupportedExtensions() || []).join(', ') || 'n/a',
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
            maxViewportDims: (gl.getParameter(gl.MAX_VIEWPORT_DIMS) || []).join('x') || 'n/a',
            maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
            maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
            maxFragmentUniformVectors: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
            maxCombinedTextureUnits: gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS)
        };
    } catch (e) {
        return { vendor: 'n/a', renderer: 'n/a', extensions: 'n/a', maxTextureSize: 'n/a', maxRenderbufferSize: 'n/a', maxViewportDims: 'n/a', maxVertexAttribs: 'n/a', maxVertexUniformVectors: 'n/a', maxFragmentUniformVectors: 'n/a', maxCombinedTextureUnits: 'n/a' };
    }
}

// --- WebGL Render Fingerprint (GPU pixel-level) ---
export function getWebGLRenderFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 64;
        canvas.height = 64;
        const gl = canvas.getContext('webgl');
        if (!gl) return 'webgl-not-supported';

        // Vertex shader
        const vsSource = `
            attribute vec2 p;
            void main() { gl_Position = vec4(p, 0.0, 1.0); }
        `;

        // Fragment shader — heavy float math that differs per GPU
        const fsSource = `
            precision mediump float;
            void main() {
                float x = gl_FragCoord.x / 64.0;
                float y = gl_FragCoord.y / 64.0;
                gl_FragColor = vec4(
                    sin(x * 12.9898 + y * 78.233) * 0.5 + 0.5,
                    cos(y * 43.758 + x * 12.345) * 0.5 + 0.5,
                    sin(x * y * 93.9898 + 47.123) * 0.5 + 0.5,
                    1.0
                );
            }
        `;

        function compileShader(src, type) {
            const s = gl.createShader(type);
            gl.shaderSource(s, src);
            gl.compileShader(s);
            return s;
        }

        const vs = compileShader(vsSource, gl.VERTEX_SHADER);
        const fs = compileShader(fsSource, gl.FRAGMENT_SHADER);
        const prog = gl.createProgram();
        gl.attachShader(prog, vs);
        gl.attachShader(prog, fs);
        gl.linkProgram(prog);
        gl.useProgram(prog);

        // Draw a full-screen quad (two triangles)
        const buf = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, buf);
        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
            -1, -1,  1, -1,  -1, 1,
            -1,  1,  1, -1,   1, 1
        ]), gl.STATIC_DRAW);

        const loc = gl.getAttribLocation(prog, 'p');
        gl.enableVertexAttribArray(loc);
        gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

        gl.drawArrays(gl.TRIANGLES, 0, 6);

        // Read pixels and hash — round to nearest 4 for noise resistance
        const pixels = new Uint8Array(64 * 64 * 4);
        gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, pixels);

        let hash = 0;
        for (let i = 0; i < pixels.length; i++) {
            hash = ((hash << 5) - hash + (Math.round(pixels[i] / 4) * 4)) | 0;
        }
        return hash.toString();
    } catch (e) {
        return 'webgl-render-error';
    }
}

// --- Constructor count (browser version signal) ---
export function getConstructorCount() {
    try {
        return Object.getOwnPropertyNames(window).filter(p => {
            try { return typeof window[p] === 'function'; } catch { return false; }
        }).length;
    } catch (e) {
        return 0;
    }
}

// --- CSS.supports() probing (browser version signal) ---
export function getCSSSupports() {
    const features = [
        'backdrop-filter: blur(1px)',
        'color: oklch(0.5 0.2 200)',
        'container-type: inline-size',
        'view-transition-name: test',
        'anchor-name: --test',
        'field-sizing: content',
        'text-wrap: balance',
        'color-mix(in srgb, red, blue)',
        'accent-color: red',
        'overscroll-behavior: contain',
        'content-visibility: auto',
        'scroll-timeline-name: test',
        'animation-timeline: scroll()',
        'font-palette: --custom',
        'color: light-dark(white, black)'
    ];
    try {
        return features.filter(f => CSS.supports(f)).join(', ');
    } catch (e) {
        return 'css-supports-error';
    }
}

// --- Event handler count (browser version signal) ---
export function getEventHandlerCount() {
    try {
        return Object.getOwnPropertyNames(window).filter(p => p.startsWith('on')).length;
    } catch (e) {
        return 0;
    }
}

// --- Intl deep probing (per-device OS locale) ---
export function getIntlFingerprint() {
    try {
        const nf = new Intl.NumberFormat().resolvedOptions();
        const df = new Intl.DateTimeFormat().resolvedOptions();
        const pr = new Intl.PluralRules().resolvedOptions();

        return [
            nf.locale,
            nf.numberingSystem,
            df.locale,
            df.calendar,
            df.timeZone,
            df.numberingSystem,
            pr.locale,
            pr.type,
            // Formatted output reflects OS-level settings
            (3.14).toLocaleString(),
            new Date(0).toLocaleString(),
            (1000000).toLocaleString()
        ].join('|');
    } catch (e) {
        return 'intl-error';
    }
}

// --- Font detection ---
export function getDetectedFonts() {
    const testFonts = [
        // Windows system fonts
        'Arial', 'Arial Black', 'Arial Narrow', 'Bahnschrift', 'Calibri', 'Cambria',
        'Cambria Math', 'Candara', 'Comic Sans MS', 'Consolas', 'Constantia', 'Corbel',
        'Courier New', 'Ebrima', 'Franklin Gothic Medium', 'Gabriola', 'Gadugi',
        'Georgia', 'Impact', 'Ink Free', 'Javanese Text', 'Leelawadee UI',
        'Lucida Console', 'Lucida Sans Unicode', 'Malgun Gothic', 'Marlett',
        'Microsoft Himalaya', 'Microsoft JhengHei', 'Microsoft New Tai Lue',
        'Microsoft PhagsPa', 'Microsoft Sans Serif', 'Microsoft Tai Le',
        'Microsoft YaHei', 'Microsoft Yi Baiti', 'MingLiU-ExtB', 'Mongolian Baiti',
        'MS Gothic', 'MS Mincho', 'MV Boli', 'Myanmar Text', 'Nirmala UI',
        'Palatino Linotype', 'Segoe MDL2 Assets', 'Segoe Print', 'Segoe Script',
        'Segoe UI', 'Segoe UI Emoji', 'Segoe UI Historic', 'Segoe UI Symbol',
        'SimSun', 'SimHei', 'NSimSun', 'Sitka', 'Sylfaen', 'Symbol', 'Tahoma',
        'Times New Roman', 'Trebuchet MS', 'Verdana', 'Webdings', 'Wingdings',
        'Yu Gothic', 'Yu Mincho',
        // macOS system fonts
        'American Typewriter', 'Andale Mono', 'Apple Chancery', 'Apple Color Emoji',
        'Apple SD Gothic Neo', 'AppleGothic', 'AppleMyungjo', 'Arial Hebrew',
        'Arial Rounded MT Bold', 'Arial Unicode MS', 'Avenir', 'Avenir Next',
        'Avenir Next Condensed', 'Ayuthaya', 'Baghdad', 'Baskerville', 'Beirut',
        'Big Caslon', 'Bodoni 72', 'Bradley Hand', 'Brush Script MT', 'Chalkboard',
        'Chalkboard SE', 'Chalkduster', 'Charter', 'Cochin', 'Copperplate', 'Courier',
        'Damascus', 'Devanagari MT', 'DIN Alternate', 'DIN Condensed', 'Euphemia UCAS',
        'Farah', 'Farisi', 'Futura', 'Geeza Pro', 'Geneva', 'Gill Sans', 'Gujarati MT',
        'Gurmukhi MN', 'Hannotate SC', 'HanziPen SC', 'Helvetica', 'Helvetica Neue',
        'Herculanum', 'Hiragino Kaku Gothic', 'Hiragino Maru Gothic Pro',
        'Hiragino Mincho ProN', 'Hiragino Sans', 'Hoefler Text', 'Inai Mathi',
        'Iowan Old Style', 'Kailasa', 'Kannada MN', 'Kefa', 'Khmer Sangam MN',
        'Kohinoor Bangla', 'Kohinoor Devanagari', 'Kohinoor Telugu', 'Krungthep',
        'Lao Sangam MN', 'Lucida Grande', 'Luminari', 'Malayalam MN', 'Marker Felt',
        'Menlo', 'Mishafi', 'Monaco', 'Mukta Mahee', 'Myanmar MN', 'Nadeem',
        'New Peninim MT', 'Noteworthy', 'Noto Nastaliq Urdu', 'Optima', 'Oriya MN',
        'Palatino', 'Papyrus', 'Phosphate', 'Plantagenet Cherokee', 'PT Mono',
        'PT Sans', 'PT Serif', 'Raanana', 'Rockwell', 'Sana', 'Sathu', 'Savoye LET',
        'SignPainter', 'Silom', 'Sinhala MN', 'Skia', 'Snell Roundhand', 'Songti SC',
        'STIX Two Math', 'Sukhumvit Set', 'Tamil MN', 'Telugu MN', 'Thonburi',
        'Times', 'Trattatello', 'Waseem', 'Zapf Dingbats', 'Zapfino',
        // Linux / Noto / Liberation
        'Bitstream Charter', 'Bitstream Vera Sans', 'Bitstream Vera Sans Mono',
        'Bitstream Vera Serif', 'DejaVu Sans', 'DejaVu Sans Mono', 'DejaVu Serif',
        'Liberation Mono', 'Liberation Sans', 'Liberation Serif', 'Nimbus Mono L',
        'Nimbus Roman No9 L', 'Nimbus Sans L', 'Noto Color Emoji', 'Noto Sans',
        'Noto Sans CJK JP', 'Noto Sans CJK KR', 'Noto Sans CJK SC', 'Noto Sans CJK TC',
        'Noto Serif', 'OpenSymbol', 'Sawasdee', 'Tlwg Typo', 'Ubuntu',
        'Ubuntu Condensed', 'Ubuntu Mono', 'URW Bookman L', 'URW Chancery L',
        'URW Gothic L', 'URW Palladio L',
        // Programming / web / brand fonts
        'Anonymous Pro', 'Cascadia Code', 'Cascadia Mono', 'Cousine', 'Dank Mono',
        'Droid Sans', 'Droid Sans Mono', 'Droid Serif', 'Fira Code', 'Fira Mono',
        'Fira Sans', 'Hack', 'IBM Plex Mono', 'IBM Plex Sans', 'IBM Plex Serif',
        'Inconsolata', 'Input Mono', 'Iosevka', 'JetBrains Mono', 'Lato',
        'Merriweather', 'Montserrat', 'Nunito', 'Open Sans', 'Operator Mono',
        'Oswald', 'Overpass', 'Poppins', 'Raleway', 'Roboto', 'Roboto Condensed',
        'Roboto Mono', 'Roboto Slab', 'Source Code Pro', 'Source Han Sans',
        'Source Sans Pro', 'Source Serif Pro', 'Work Sans'
    ];
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testStr = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    function getWidth(font) {
        ctx.font = testSize + ' ' + font;
        return ctx.measureText(testStr).width;
    }

    const baseWidths = baseFonts.map(f => getWidth(f));
    const detected = [];

    for (const font of testFonts) {
        for (let i = 0; i < baseFonts.length; i++) {
            if (getWidth(font + ',' + baseFonts[i]) !== baseWidths[i]) {
                detected.push(font);
                break;
            }
        }
    }
    return detected;
}
