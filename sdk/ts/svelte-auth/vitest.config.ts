import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

// Node 25 and later define a global localStorage (the webstorage feature)
// that is unusable without --localstorage-file and shadows jsdom's, so the
// test workers turn it off wherever this Node knows the flag.
const webstorageOff = process.allowedNodeEnvironmentFlags.has('--experimental-webstorage')
  ? ['--no-experimental-webstorage']
  : [];

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['test/**/*.test.ts'],
    pool: 'forks',
    poolOptions: { forks: { execArgv: webstorageOff } },
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
