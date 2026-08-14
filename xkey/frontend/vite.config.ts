import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'path';

export default defineConfig({
  plugins: [svelte()],
  resolve: {
    alias: {
      '$lib': path.resolve('./src/lib'),
      // The console subpath must precede the bare package alias: Vite string
      // aliases match by prefix, so '@go-xkms/sdk' would otherwise swallow it.
      '@go-xkms/sdk/ssh-console': path.resolve('../../sdk/ts/src/ssh-console.ts'),
      '@go-xkms/sdk': path.resolve('../../sdk/ts/src/index.ts'),
      // Pin @go-xkms/sdk's bare xterm imports to this app's copy so only one
      // Terminal implementation ships (sdk/ts is aliased to raw source above,
      // so its own node_modules copy would otherwise resolve independently).
      '@xterm/xterm': path.resolve('./node_modules/@xterm/xterm'),
      '@xterm/addon-fit': path.resolve('./node_modules/@xterm/addon-fit'),
    },
    dedupe: ['@xterm/xterm', '@xterm/addon-fit'],
  },
  build: {
    outDir: 'dist',
    chunkSizeWarningLimit: 1600,
  },
});
