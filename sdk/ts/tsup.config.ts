import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2021',
  // xterm is a peer the consuming app provides; keep it external.
  external: ['@xterm/xterm', '@xterm/addon-fit'],
});
