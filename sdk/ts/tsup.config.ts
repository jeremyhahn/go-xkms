import { defineConfig } from 'tsup';

export default defineConfig({
  // Two entries: the main client, and the xterm-backed console on its own
  // subpath so a web app can code-split the terminal (and its xterm
  // dependency) out of the initial bundle.
  entry: ['src/index.ts', 'src/ssh-console.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2021',
  // xterm is a peer the consuming app provides; keep it external.
  external: ['@xterm/xterm', '@xterm/addon-fit'],
});
