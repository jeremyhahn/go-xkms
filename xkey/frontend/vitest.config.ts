import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'path';

// Node 22.4+ knows the flag and Node 26 needs it (#2167); the CI image's
// Node 20 rejects it and every worker exits.
const webstorageOff = process.allowedNodeEnvironmentFlags.has('--experimental-webstorage') ? ['--no-experimental-webstorage'] : [];

// Mirrors vite.config.ts's resolve.alias for $lib. Kept standalone (rather
// than merging vite.config.ts's plugin list) so the Svelte plugin is
// instantiated exactly once, with vitest-appropriate options (hot: false).
export default defineConfig({
  plugins: [svelte({ hot: false })],
  resolve: {
    alias: {
      '$lib': path.resolve('./src/lib'),
    },
    conditions: ['browser'],
  },
  test: {
    environment: 'jsdom',
    globals: true,
    // Node 26 enables Web Storage by default; its global localStorage
    // shadows jsdom's (#2167). Workers run without it.
    poolOptions: {
      forks: { execArgv: webstorageOff },
      threads: { execArgv: webstorageOff },
    },
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      reporter: ['text', 'lcov'],
      include: ['src/lib/**/*.{ts,svelte}', 'src/views/**/*.svelte'],
      exclude: ['src/**/*.d.ts', 'src/wailsjs/**'],
    },
  },
});
