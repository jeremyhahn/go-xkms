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

/** Theme store: persists the daisyUI theme and stamps it on <html>. */

export type Theme = "xkms-dark" | "xkms-light";

const STORAGE_KEY = "xkms_theme";
const DEFAULT_THEME: Theme = "xkms-dark";

function readStored(): Theme {
  if (typeof localStorage === "undefined") {
    return DEFAULT_THEME;
  }
  const v = localStorage.getItem(STORAGE_KEY);
  return v === "xkms-light" || v === "xkms-dark" ? v : DEFAULT_THEME;
}

const initialTheme = readStored();
let _theme = $state<Theme>(initialTheme);

function apply(theme: Theme): void {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", theme);
  }
}

// One-time apply of the persisted theme at module load. Uses the plain
// initial value (not the reactive $state) so this is not a reactive read.
apply(initialTheme);

export const themeStore = {
  get theme(): Theme {
    return _theme;
  },
};

/** setTheme persists and applies a theme. */
export function setTheme(theme: Theme): void {
  _theme = theme;
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(STORAGE_KEY, theme);
  }
  apply(theme);
}

/** toggleTheme flips between dark and light. */
export function toggleTheme(): void {
  setTheme(_theme === "xkms-dark" ? "xkms-light" : "xkms-dark");
}
