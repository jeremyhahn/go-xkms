// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

/**
 * isWailsRuntime reports whether the page is being served inside a Wails
 * desktop shell (window.go bindings / window.runtime bridge present). Web
 * UIs that ship both as a hosted SPA and as a desktop app use this to pick
 * between the REST client and native Wails bindings.
 */
export function isWailsRuntime(): boolean {
  if (typeof globalThis === 'undefined') {
    return false;
  }
  const w = globalThis as Record<string, unknown>;
  return w['go'] !== undefined || w['runtime'] !== undefined;
}
