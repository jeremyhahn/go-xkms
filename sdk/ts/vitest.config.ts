import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      // Tests and pure type declarations carry no executable logic; counting
      // them would inflate the ratio rather than measure tested behaviour.
      exclude: ['src/**/*.test.ts', 'src/types/**', 'src/index.ts'],
      // The 90% floor is the project rule; the suite currently sits near 100%
      // on every axis, so a drop this large means tests were deleted rather
      // than that coverage drifted.
      thresholds: { statements: 90, lines: 90, functions: 90, branches: 90 },
    },
  },
});
