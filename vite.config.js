import { defineConfig } from 'vite';

export default defineConfig({
    build: {
        lib: {
            entry: 'src/lib.js',
            name: 'NitroFingerprint',
            formats: ['es', 'iife'],
            fileName: (format) => {
                if (format === 'es') return 'index.mjs';
                if (format === 'iife') return 'index.global.js';
            }
        }
    }
});
