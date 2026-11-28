import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// Node 22.4+ knows the flag and Node 26 needs it (#2167); the CI image's
// Node 20 rejects it and every worker exits.
const webstorageOff = process.allowedNodeEnvironmentFlags.has('--experimental-webstorage') ? ['--no-experimental-webstorage'] : [];

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  test: {
    environment: 'jsdom',
    globals: true,
    // Node 26 enables Web Storage by default; its global localStorage
    // shadows jsdom's (#2167). Workers run without it.
    poolOptions: {
      forks: { execArgv: webstorageOff },
      threads: { execArgv: webstorageOff },
    },
    include: ['test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,svelte}'],
      exclude: ['src/index.ts', 'src/**/*.d.ts'],
      thresholds: { statements: 90, lines: 90, functions: 90, branches: 90 },
    },
  },
  resolve: {
    conditions: ['browser', 'import', 'module', 'default'],
  },
});
