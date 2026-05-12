# Theming

## Dark/Light Mode

The GUI supports dark and light themes via TailwindCSS `dark:` class variants. Theme state is managed by the `theme` Svelte store.

### How It Works

1. On startup, `initTheme()` checks `localStorage` for a saved preference
2. If none, it reads the OS preference via `prefers-color-scheme` media query
3. The `dark` class is toggled on `document.documentElement`
4. TailwindCSS applies `dark:` variant styles throughout the app

### Toggle

The Sidebar footer includes a theme toggle button. Programmatically:

```typescript
import { toggleTheme } from '@trustedca/shared/stores/theme';
toggleTheme();
```

### Persistence

Theme preference is stored in `localStorage` under the key `trustedca-theme` with values `light` or `dark`.

## TailwindCSS Configuration

The project uses TailwindCSS 3 with the `class` dark mode strategy. All shared components use the `dark:` variant for styling.

Color palette:
- **Primary**: `blue-600` / `blue-400` (dark)
- **Backgrounds**: `white` / `slate-800` (dark), `slate-50` / `slate-900` (dark, sidebar)
- **Borders**: `slate-200` / `slate-700` (dark)
- **Text**: `slate-900` / `slate-100` (dark, headings), `slate-600` / `slate-300` (dark, body)

Status colors follow the `StatusBadge` mapping (see [Component Library](component-library.md)).
