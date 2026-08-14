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

import { mount } from "svelte";
import App from "./App.svelte";
import { setupAuth } from "./lib/auth.ts";
import { bootstrapDesktop } from "./lib/desktop.ts";
import { showToast } from "./stores/toast.svelte.ts";
import "./app.css";

// Wire the shared auth package before mount: this configures the token store
// and installs the global 401-renew-and-replay fetch interceptor, so the very
// first request already recovers from a lapsed access token.
setupAuth();

// Desktop (Wails) bootstrap: point the SDK at the shell-provided engine and,
// in standalone mode, install the loopback token so the owner lands directly
// on the console. A no-op in a plain browser. Fire-and-forget: the auth store
// flip re-renders the app when it resolves.
void bootstrapDesktop();

// Surface otherwise-unhandled errors as toasts instead of letting the UI
// silently break. Neither handler suppresses the error — devtools still get
// the full stack.
if (typeof window !== "undefined") {
  window.addEventListener("unhandledrejection", (e) => {
    const reason = e.reason;
    showToast("error", reason instanceof Error ? reason.message : String(reason));
  });
}

const target = document.getElementById("app");
if (target === null) {
  throw new Error("mount target #app not found");
}

export default mount(App, { target });
