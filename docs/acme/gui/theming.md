# Theming

> **Status: REFERENCE** · Last verified: 2026-10-12
> Legacy, unabsorbed notes on dark/light mode in the ACME SPAs.

## Theme store

`pkg/acme/web/packages/shared/src/stores/theme.ts` holds the theme state:

- `themeMode` is a writable store: `'light' | 'dark' | 'system'`.
- `theme` is derived from it and resolves to `'light' | 'dark'`. `system`
  follows `prefers-color-scheme`.
- `initTheme()` applies the theme and, in `system` mode, tracks OS changes.
- `setThemeMode(mode)` sets the mode, and `toggleTheme()` flips between light
  and dark. Both persist to `localStorage` under `trustedca-theme`.
- Applying a theme toggles the `dark` class on `document.documentElement`.

The Sidebar footer has a light/dark toggle. Both apps' Settings views offer
Light, Dark and System.

## Tailwind configuration

The SPAs use **Tailwind CSS 4** through `@tailwindcss/vite`, plus daisyUI 5.
Each app's `src/app.css` begins:

```css
@import "tailwindcss";
@source "../../shared/src/**/*.{svelte,ts,js}";
@plugin "daisyui";
```

There is no `tailwind.config.js` and no `@custom-variant dark` rule. Under
Tailwind 4 the `dark:` variant therefore matches `prefers-color-scheme: dark`,
not the `dark` class. As a result, the in-app toggle and the Light/Dark
settings change the store and the class but not the `dark:` styles: the
styles follow the OS setting. Making the toggle drive the styles would need
`@custom-variant dark (&:where(.dark, .dark *));` in each `app.css`.

Color palette used by the shared components:
- **Primary**: `blue-600` / `blue-400` (dark)
- **Backgrounds**: `white` / `slate-800` (dark), `slate-50` / `slate-900` (dark, sidebar)
- **Borders**: `slate-200` / `slate-700` (dark)
- **Text**: `slate-900` / `slate-100` (dark, headings), `slate-600` / `slate-300` (dark, body)

Status colors follow the `StatusBadge` mapping (see [Component Library](component-library.md)).
