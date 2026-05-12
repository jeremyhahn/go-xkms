import { writable, derived } from 'svelte/store';

export type ThemeMode = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'trustedca-theme';

function getSystemPreference(): ResolvedTheme {
  if (typeof window === 'undefined') {
    return 'dark';
  }
  return window.matchMedia('(prefers-color-scheme: dark)').matches
    ? 'dark'
    : 'light';
}

function getInitialMode(): ThemeMode {
  if (typeof window === 'undefined') {
    return 'system';
  }
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === 'light' || stored === 'dark' || stored === 'system') {
    return stored;
  }
  return 'system';
}

function resolveTheme(mode: ThemeMode): ResolvedTheme {
  if (mode === 'system') {
    return getSystemPreference();
  }
  return mode;
}

/** The user-selected mode: light, dark, or system. */
export const themeMode = writable<ThemeMode>(getInitialMode());

/** The resolved theme after applying system preference detection. */
export const theme = derived<typeof themeMode, ResolvedTheme>(
  themeMode,
  ($mode) => resolveTheme($mode),
);

/** Apply the resolved theme to the document root element. */
function applyTheme(resolved: ResolvedTheme): void {
  if (typeof document === 'undefined') {
    return;
  }
  document.documentElement.classList.toggle('dark', resolved === 'dark');
}

/** Set the theme mode explicitly. */
export function setThemeMode(mode: ThemeMode): void {
  themeMode.set(mode);
  if (typeof window !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, mode);
  }
}

/** Toggle between light and dark themes (skips system). */
export function toggleTheme(): void {
  themeMode.update((current) => {
    const resolved = resolveTheme(current);
    const next: ThemeMode = resolved === 'dark' ? 'light' : 'dark';
    if (typeof window !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, next);
    }
    return next;
  });
}

/** Initialise theme on app startup. Call once in the root component. */
export function initTheme(): void {
  // Subscribe to the resolved theme and apply to DOM.
  const unsubscribe = theme.subscribe(applyTheme);

  // Listen for system preference changes when in "system" mode.
  if (typeof window !== 'undefined') {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = () => {
      let currentMode: ThemeMode = 'system';
      themeMode.subscribe((m) => { currentMode = m; })();
      if (currentMode === 'system') {
        // Re-trigger the derived store by setting the same value.
        themeMode.set('system');
      }
    };
    mediaQuery.addEventListener('change', handleChange);

    (window as any).__themeUnsub = () => {
      unsubscribe();
      mediaQuery.removeEventListener('change', handleChange);
    };
  }
}
