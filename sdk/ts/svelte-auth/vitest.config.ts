import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  test: {
    environment: 'jsdom',
    globals: true,
    // Node 26 enables Web Storage by default; its global localStorage
    // shadows jsdom's (#2167). Workers run without it.
    poolOptions: {
      forks: { execArgv: ['--no-experimental-webstorage'] },
      threads: { execArgv: ['--no-experimental-webstorage'] },
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
