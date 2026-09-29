import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'path';

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
