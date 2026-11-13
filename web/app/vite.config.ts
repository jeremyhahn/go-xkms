// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

/// <reference types="vitest" />
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";

// XKMS_DEV_API is the dev-server proxy target for a locally running xkmsd.
// Defaults to the standard REST TLS port; `secure: false` accepts the
// self-issued CA-backed cert, and `ws: true` proxies the SSH console upgrade.
const devAPI = process.env.XKMS_DEV_API ?? "https://localhost:8443";
const proxyTarget = { target: devAPI, secure: false, ws: true, changeOrigin: true };

export default defineConfig({
  // base is "./" so Vite emits RELATIVE asset paths (./assets/index.js) in
  // index.html, which resolve correctly in every deployment context:
  //   - daemon serves index.html at /ui/  → ./assets → /ui/assets  ✓
  //   - Wails desktop serves it at /       → ./assets → /assets     ✓
  // An absolute /ui/ base would break the Wails shell (assets embedded at
  // root), so keep this relative.
  base: "./",
  plugins: [svelte(), tailwindcss()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  resolve: {
    // Component tests mount real components, so Svelte must resolve to its
    // browser build: without the browser condition `svelte` resolves to
    // index-server.js and every mount() throws lifecycle_function_unavailable.
    // Spread rather than pass [] on a normal build — an empty array REPLACES
    // Vite's default condition list instead of extending it, which silently
    // changes how every dependency resolves.
    ...(process.env.VITEST !== undefined ? { conditions: ["browser"] } : {}),
    alias: {
      $lib: "/src/lib",
      $stores: "/src/stores",
      $components: "/src/components",
      $views: "/src/views",
    },
  },
  server: {
    port: 5174,
    strictPort: false,
    proxy: {
      "/api": proxyTarget,
      "/xkms": proxyTarget,
      "/health": proxyTarget,
      "/v1": proxyTarget,
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    // Node 26 enables Web Storage by default; its global localStorage
    // shadows jsdom's (#2167). Workers run without it.
    poolOptions: {
      forks: { execArgv: ["--no-experimental-webstorage"] },
      threads: { execArgv: ["--no-experimental-webstorage"] },
    },
    setupFiles: ["./test/setup.ts"],
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reportsDirectory: "./coverage",
      reporter: ["text", "lcov"],
      include: ["src/**/*.{ts,svelte}"],
      // main.ts is the browser bootstrap (never imported by a test) and
      // app.d.ts is types only.
      exclude: ["src/main.ts", "src/**/*.d.ts"],
      // Statements/lines/functions hold the project's 90% rule. The branch
      // floor is lower because the Svelte compiler emits implicit branches
      // for every `{#if}`, `{#each}` key path, and optional prop — chasing
      // those to 90% buys assertions about generated code, not behaviour.
      thresholds: { statements: 90, lines: 90, functions: 90, branches: 80 },
    },
  },
});
