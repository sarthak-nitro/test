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

// --- Canvas fingerprint (noise-resistant) ---
export function getCanvasFingerprint() {
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

        // Read raw pixels and round each value to nearest 4
        // This absorbs Safari's ±1-2 noise in private mode
        const pixels = ctx.getImageData(0, 0, 200, 50).data;
        let rounded = '';
        for (let i = 0; i < pixels.length; i++) {
            rounded += (Math.round(pixels[i] / 4) * 4);
        }
        return rounded;
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
        'Arial', 'Courier New', 'Georgia', 'Helvetica', 'Times New Roman',
        'Verdana', 'Comic Sans MS', 'Impact', 'Trebuchet MS', 'Palatino',
        'Lucida Console', 'Tahoma', 'Monaco', 'Menlo', 'Consolas'
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
