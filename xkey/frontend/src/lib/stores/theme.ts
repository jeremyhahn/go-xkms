import { writable, derived } from 'svelte/store';

export type ThemeMode = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'xkey-theme';

function getSystemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function loadSavedTheme(): ThemeMode {
  if (typeof window === 'undefined') return 'system';
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === 'light' || saved === 'dark' || saved === 'system') {
    return saved;
  }
  return 'system';
}

export const theme = writable<ThemeMode>(loadSavedTheme());

export const effectiveTheme = derived(theme, ($theme) => {
  if ($theme === 'system') {
    return getSystemTheme();
  }
  return $theme;
});

function applyTheme(effective: 'light' | 'dark'): void {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('data-theme', effective);
  if (effective === 'dark') {
    document.documentElement.classList.add('dark');
  } else {
    document.documentElement.classList.remove('dark');
  }
}

export function initTheme(): void {
  const saved = loadSavedTheme();
  theme.set(saved);

  const effective = saved === 'system' ? getSystemTheme() : saved;
  applyTheme(effective);

  effectiveTheme.subscribe((eff) => {
    applyTheme(eff);
  });

  if (typeof window !== 'undefined') {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', () => {
      let currentMode: ThemeMode = 'system';
      theme.subscribe((v) => { currentMode = v; })();
      if (currentMode === 'system') {
        applyTheme(getSystemTheme());
      }
    });
  }
}

export function setTheme(mode: ThemeMode): void {
  theme.set(mode);
  if (typeof window !== 'undefined') {
    localStorage.setItem(STORAGE_KEY, mode);
  }
}

export function toggleTheme(): void {
  theme.update((current) => {
    let next: ThemeMode;
    if (current === 'light') {
      next = 'dark';
    } else if (current === 'dark') {
      next = 'system';
    } else {
      next = 'light';
    }
    if (typeof window !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, next);
    }
    return next;
  });
}
