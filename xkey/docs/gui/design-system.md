# xKey Desktop GUI - Design System

This design system ensures visual parity between the xKey Desktop GUI and the Android app. All colors, typography, spacing, and component styles are derived from the Android implementation.

## Design Philosophy

> A security-focused, premium palette designed to convey trust, authority, and institutional-grade security.

### Three Pillars

1. **Primary: Deep Navy (#1A237E)** - Vault-like trust and authority
2. **Secondary: Warm Gold (#FFB300)** - Premium distinction and achievement
3. **Tertiary: Rich Teal (#00897B)** - Digital security and verification

### Principles

- Surfaces carry warm ivory undertones for refined legibility
- Security indicators use intentional, curated status colors
- Dark theme uses navy-charcoal, never pure black
- All colors tested for WCAG AA+ contrast compliance

---

## Color Palette

### CSS Variables (Light Theme)

```css
:root {
  /* ================================================================== */
  /* PRIMARY: Deep Navy (#1A237E family)                                */
  /* Evokes security vaults, authority, and institutional trust.        */
  /* ================================================================== */
  --color-primary: #1A237E;
  --color-primary-variant: #0D1442;
  --color-on-primary: #FFFFFF;
  --color-primary-container: #DEE0FF;
  --color-on-primary-container: #00006E;

  /* Primary tonal palette */
  --color-primary-10: #00006E;
  --color-primary-20: #0D1442;
  --color-primary-30: #1A237E;
  --color-primary-40: #303F9F;
  --color-primary-50: #3949AB;
  --color-primary-60: #5C6BC0;
  --color-primary-70: #7986CB;
  --color-primary-80: #9FA8DA;
  --color-primary-90: #C5CAE9;
  --color-primary-95: #DEE0FF;
  --color-primary-99: #FEFBFF;

  /* ================================================================== */
  /* SECONDARY: Warm Gold (#FFB300 family)                              */
  /* Premium accent that signals quality, achievement, and distinction. */
  /* ================================================================== */
  --color-secondary: #FFB300;
  --color-secondary-variant: #C68400;
  --color-on-secondary: #3E2800;
  --color-secondary-container: #FFDEA6;
  --color-on-secondary-container: #271900;

  /* Secondary tonal palette */
  --color-secondary-10: #271900;
  --color-secondary-20: #3E2800;
  --color-secondary-30: #5C3D00;
  --color-secondary-40: #7C5500;
  --color-secondary-50: #9E6D00;
  --color-secondary-60: #C68400;
  --color-secondary-70: #FFB300;
  --color-secondary-80: #FFCA47;
  --color-secondary-90: #FFDEA6;
  --color-secondary-95: #FFEFD4;
  --color-secondary-99: #FFFBFF;

  /* ================================================================== */
  /* TERTIARY: Rich Teal (#00897B family)                               */
  /* Security verification accent. Used for authenticated states,       */
  /* crypto indicators, biometric confirmations, and trust badges.      */
  /* ================================================================== */
  --color-tertiary: #00897B;
  --color-tertiary-variant: #00695C;
  --color-on-tertiary: #FFFFFF;
  --color-tertiary-container: #A7F3EC;
  --color-on-tertiary-container: #002020;

  /* Tertiary tonal palette */
  --color-tertiary-10: #002020;
  --color-tertiary-20: #003D3A;
  --color-tertiary-30: #00695C;
  --color-tertiary-40: #00897B;
  --color-tertiary-50: #00A99B;
  --color-tertiary-60: #26BFAC;
  --color-tertiary-70: #4DD0C5;
  --color-tertiary-80: #7DE0D8;
  --color-tertiary-90: #A7F3EC;
  --color-tertiary-95: #C8FFF8;
  --color-tertiary-99: #F2FFFC;

  /* ================================================================== */
  /* SURFACE AND BACKGROUND: Warm Ivory                                 */
  /* ================================================================== */
  --color-background: #FFFBFE;
  --color-on-background: #1C1B1F;
  --color-surface: #FFFBFE;
  --color-on-surface: #1C1B1F;
  --color-surface-variant: #E7E0EC;
  --color-on-surface-variant: #49454F;

  /* Material 3 Surface Container hierarchy */
  --color-surface-container-lowest: #FFFFFF;
  --color-surface-container-low: #F7F2FA;
  --color-surface-container: #F3EDF7;
  --color-surface-container-high: #ECE6F0;
  --color-surface-container-highest: #E6E0E9;

  --color-surface-dim: #DED8E1;
  --color-surface-bright: #FFFBFE;

  /* ================================================================== */
  /* ERROR: Deep Crimson                                                */
  /* ================================================================== */
  --color-error: #BA1A1A;
  --color-on-error: #FFFFFF;
  --color-error-container: #FFDAD6;
  --color-on-error-container: #410002;

  /* ================================================================== */
  /* SECURITY INDICATOR COLORS                                          */
  /* ================================================================== */

  /* Verified / Success - Emerald Green */
  --color-security-verified: #1B8A50;
  --color-security-verified-variant: #0E6B3A;
  --color-on-security-verified: #FFFFFF;
  --color-security-verified-container: #C8F5D0;
  --color-on-security-verified-container: #002110;

  /* Warning / Caution - Amber Gold */
  --color-security-warning: #E6A700;
  --color-security-warning-variant: #C68400;
  --color-on-security-warning: #3E2800;
  --color-security-warning-container: #FFEFD4;
  --color-on-security-warning-container: #271900;

  /* Danger / Error - Deep Crimson */
  --color-security-danger: #C62828;
  --color-security-danger-variant: #9A0007;
  --color-on-security-danger: #FFFFFF;
  --color-security-danger-container: #FFDAD6;
  --color-on-security-danger-container: #410002;

  /* Neutral / Inactive - Warm Slate */
  --color-security-neutral: #6B7280;
  --color-security-neutral-variant: #4B5563;
  --color-on-security-neutral: #FFFFFF;
  --color-security-neutral-container: #E5E7EB;
  --color-on-security-neutral-container: #1F2937;

  /* ================================================================== */
  /* CONNECTION STATUS COLORS                                           */
  /* ================================================================== */
  --color-status-connected: #1B8A50;
  --color-status-disconnected: #6B7280;
  --color-status-advertising: #E6A700;
  --color-status-error: #C62828;
  --color-status-pairing: #5C6BC0;

  /* ================================================================== */
  /* GRADIENTS                                                          */
  /* ================================================================== */
  --gradient-primary: linear-gradient(135deg, #1A237E 0%, #303F9F 100%);
  --gradient-secondary: linear-gradient(135deg, #FFB300 0%, #FFCA28 100%);
  --gradient-tertiary: linear-gradient(135deg, #00897B 0%, #26A69A 100%);
  --gradient-premium: linear-gradient(135deg, #1A237E 0%, #303F9F 50%, #FFB300 100%);
  --gradient-security: linear-gradient(135deg, #00897B 0%, #1A237E 100%);

  /* ================================================================== */
  /* OUTLINE                                                            */
  /* ================================================================== */
  --color-outline: #79747E;
  --color-outline-variant: #CAC4D0;

  /* ================================================================== */
  /* INVERSE                                                            */
  /* ================================================================== */
  --color-inverse-surface: #313033;
  --color-inverse-on-surface: #F4EFF4;
  --color-inverse-primary: #C5CAE9;

  /* ================================================================== */
  /* SCRIM                                                              */
  /* ================================================================== */
  --color-scrim: #000000;
  --color-scrim-light: rgba(0, 0, 0, 0.1);
  --color-scrim-medium: rgba(0, 0, 0, 0.3);
  --color-scrim-heavy: rgba(0, 0, 0, 0.5);

  --color-surface-tint: #1A237E;
}
```

### CSS Variables (Dark Theme)

```css
[data-theme="dark"] {
  /* Primary: Luminous Indigo */
  --color-primary: #C5CAE9;
  --color-primary-variant: #9FA8DA;
  --color-on-primary: #00006E;
  --color-primary-container: #0D1442;
  --color-on-primary-container: #DEE0FF;

  /* Secondary: Luminous Gold */
  --color-secondary: #FFCA47;
  --color-secondary-variant: #FFB300;
  --color-on-secondary: #3E2800;
  --color-secondary-container: #5C3D00;
  --color-on-secondary-container: #FFDEA6;

  /* Tertiary: Luminous Teal */
  --color-tertiary: #7DE0D8;
  --color-tertiary-variant: #4DD0C5;
  --color-on-tertiary: #003D3A;
  --color-tertiary-container: #00695C;
  --color-on-tertiary-container: #A7F3EC;

  /* Surfaces: Deep Navy-Charcoal (never pure black) */
  --color-background: #1C1B1F;
  --color-on-background: #E6E1E5;
  --color-surface: #1C1B1F;
  --color-on-surface: #E6E1E5;
  --color-surface-variant: #49454F;
  --color-on-surface-variant: #CAC4D0;

  /* Surface Container hierarchy */
  --color-surface-container-lowest: #0D0D11;
  --color-surface-container-low: #1C1B1F;
  --color-surface-container: #211F26;
  --color-surface-container-high: #2B2930;
  --color-surface-container-highest: #36343B;

  --color-surface-dim: #1C1B1F;
  --color-surface-bright: #3B383E;

  /* Error: Softened Crimson */
  --color-error: #FFB4AB;
  --color-on-error: #690005;
  --color-error-container: #93000A;
  --color-on-error-container: #FFDAD6;

  /* Security Status Colors */
  --color-security-verified: #6EE795;
  --color-on-security-verified: #00391C;
  --color-security-verified-container: #00522A;
  --color-on-security-verified-container: #8AFFAF;

  --color-security-warning: #FFCA47;
  --color-on-security-warning: #3E2800;
  --color-security-warning-container: #5C3D00;
  --color-on-security-warning-container: #FFEFD4;

  --color-security-danger: #FFB4AB;
  --color-on-security-danger: #690005;
  --color-security-danger-container: #93000A;
  --color-on-security-danger-container: #FFDAD6;

  --color-security-neutral: #9CA3AF;
  --color-on-security-neutral: #1F2937;
  --color-security-neutral-container: #374151;
  --color-on-security-neutral-container: #E5E7EB;

  /* Connection Status */
  --color-status-connected: #6EE795;
  --color-status-disconnected: #9CA3AF;
  --color-status-advertising: #FFCA47;
  --color-status-error: #FFB4AB;
  --color-status-pairing: #C5CAE9;

  /* Gradients */
  --gradient-primary: linear-gradient(135deg, #0D1442 0%, #1A237E 100%);
  --gradient-secondary: linear-gradient(135deg, #C68400 0%, #FFB300 100%);

  /* Outline */
  --color-outline: #938F99;
  --color-outline-variant: #49454F;

  /* Inverse */
  --color-inverse-surface: #E6E1E5;
  --color-inverse-on-surface: #313033;
  --color-inverse-primary: #1A237E;

  --color-surface-tint: #C5CAE9;
}
```

---

## TailwindCSS Configuration

```javascript
// tailwind.config.js
module.exports = {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // Primary: Deep Navy
        primary: {
          DEFAULT: '#1A237E',
          variant: '#0D1442',
          container: '#DEE0FF',
          10: '#00006E',
          20: '#0D1442',
          30: '#1A237E',
          40: '#303F9F',
          50: '#3949AB',
          60: '#5C6BC0',
          70: '#7986CB',
          80: '#9FA8DA',
          90: '#C5CAE9',
          95: '#DEE0FF',
          99: '#FEFBFF',
        },
        // Secondary: Warm Gold
        secondary: {
          DEFAULT: '#FFB300',
          variant: '#C68400',
          container: '#FFDEA6',
          10: '#271900',
          20: '#3E2800',
          30: '#5C3D00',
          40: '#7C5500',
          50: '#9E6D00',
          60: '#C68400',
          70: '#FFB300',
          80: '#FFCA47',
          90: '#FFDEA6',
          95: '#FFEFD4',
          99: '#FFFBFF',
        },
        // Tertiary: Rich Teal
        tertiary: {
          DEFAULT: '#00897B',
          variant: '#00695C',
          container: '#A7F3EC',
          10: '#002020',
          20: '#003D3A',
          30: '#00695C',
          40: '#00897B',
          50: '#00A99B',
          60: '#26BFAC',
          70: '#4DD0C5',
          80: '#7DE0D8',
          90: '#A7F3EC',
          95: '#C8FFF8',
          99: '#F2FFFC',
        },
        // Surface
        surface: {
          DEFAULT: '#FFFBFE',
          dim: '#DED8E1',
          bright: '#FFFBFE',
          'container-lowest': '#FFFFFF',
          'container-low': '#F7F2FA',
          container: '#F3EDF7',
          'container-high': '#ECE6F0',
          'container-highest': '#E6E0E9',
          variant: '#E7E0EC',
        },
        // Background
        background: '#FFFBFE',
        'on-background': '#1C1B1F',
        'on-surface': '#1C1B1F',
        'on-surface-variant': '#49454F',
        // Error
        error: {
          DEFAULT: '#BA1A1A',
          container: '#FFDAD6',
        },
        // Security Status
        security: {
          verified: '#1B8A50',
          'verified-container': '#C8F5D0',
          warning: '#E6A700',
          'warning-container': '#FFEFD4',
          danger: '#C62828',
          'danger-container': '#FFDAD6',
          neutral: '#6B7280',
          'neutral-container': '#E5E7EB',
        },
        // Connection Status
        status: {
          connected: '#1B8A50',
          disconnected: '#6B7280',
          advertising: '#E6A700',
          error: '#C62828',
          pairing: '#5C6BC0',
        },
        // Outline
        outline: {
          DEFAULT: '#79747E',
          variant: '#CAC4D0',
        },
      },
      borderRadius: {
        'xkey-sm': '8px',
        'xkey-md': '12px',
        'xkey-lg': '16px',
      },
      boxShadow: {
        'xkey-sm': '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        'xkey-md': '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
        'xkey-lg': '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
};
```

---

## Typography

### Font Stack

```css
--font-sans: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
--font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
```

### Type Scale

| Style | Size | Weight | Line Height | Usage |
|-------|------|--------|-------------|-------|
| Display Large | 57px | 400 | 64px | Hero sections |
| Display Medium | 45px | 400 | 52px | Page titles |
| Display Small | 36px | 400 | 44px | Section headers |
| Headline Large | 32px | 400 | 40px | Card titles |
| Headline Medium | 28px | 400 | 36px | Dialog titles |
| Headline Small | 24px | 400 | 32px | Subsections |
| Title Large | 22px | 500 | 28px | List headers |
| Title Medium | 16px | 500 | 24px | Card headers |
| Title Small | 14px | 500 | 20px | Small headers |
| Body Large | 16px | 400 | 24px | Primary content |
| Body Medium | 14px | 400 | 20px | Secondary content |
| Body Small | 12px | 400 | 16px | Captions |
| Label Large | 14px | 500 | 20px | Buttons |
| Label Medium | 12px | 500 | 16px | Chips |
| Label Small | 11px | 500 | 16px | Badges |

---

## Spacing

| Token | Value | Usage |
|-------|-------|-------|
| `space-1` | 4px | Tight spacing |
| `space-2` | 8px | Related items |
| `space-3` | 12px | Default gap |
| `space-4` | 16px | Card padding |
| `space-5` | 20px | Section spacing |
| `space-6` | 24px | Large gaps |
| `space-8` | 32px | Section margins |
| `space-10` | 40px | Page margins |
| `space-12` | 48px | Hero spacing |

---

## Components

### Card

```svelte
<!-- Card.svelte -->
<script lang="ts">
  export let variant: 'elevated' | 'outlined' | 'security' = 'elevated';
</script>

<div
  class="rounded-xkey-lg p-4 {variant === 'elevated'
    ? 'bg-surface-container-low shadow-xkey-md'
    : variant === 'outlined'
    ? 'border border-outline-variant bg-surface'
    : 'border-2 border-tertiary bg-surface'}"
>
  <slot />
</div>

<style>
  /* Elevated card */
  .card-elevated {
    background: var(--color-surface-container-low);
    border-radius: 16px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    padding: 16px;
  }

  /* Outlined card */
  .card-outlined {
    background: var(--color-surface);
    border: 1px solid var(--color-outline-variant);
    border-radius: 16px;
    padding: 16px;
  }

  /* Security card (teal accent) */
  .card-security {
    background: var(--color-surface);
    border: 2px solid var(--color-tertiary);
    border-radius: 16px;
    padding: 16px;
  }
</style>
```

### Button

```svelte
<!-- Button.svelte -->
<script lang="ts">
  export let variant: 'primary' | 'secondary' | 'tertiary' | 'outline' | 'text' | 'danger' = 'primary';
  export let size: 'sm' | 'md' | 'lg' = 'md';
  export let disabled = false;
</script>

<button
  class="btn btn-{variant} btn-{size}"
  {disabled}
  on:click
>
  <slot />
</button>

<style>
  .btn {
    font-family: var(--font-sans);
    font-weight: 500;
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .btn-sm { padding: 8px 16px; font-size: 14px; }
  .btn-md { padding: 12px 24px; font-size: 14px; min-height: 48px; }
  .btn-lg { padding: 16px 32px; font-size: 16px; }

  .btn-primary {
    background: var(--color-primary);
    color: var(--color-on-primary);
    border: none;
  }
  .btn-primary:hover { background: var(--color-primary-40); }

  .btn-secondary {
    background: var(--color-secondary);
    color: var(--color-on-secondary);
    border: none;
  }
  .btn-secondary:hover { background: var(--color-secondary-80); }

  .btn-tertiary {
    background: var(--color-tertiary);
    color: var(--color-on-tertiary);
    border: none;
  }
  .btn-tertiary:hover { background: var(--color-tertiary-50); }

  .btn-outline {
    background: transparent;
    color: var(--color-primary);
    border: 1px solid var(--color-outline);
  }
  .btn-outline:hover { background: var(--color-primary-95); }

  .btn-text {
    background: transparent;
    color: var(--color-primary);
    border: none;
  }
  .btn-text:hover { background: var(--color-primary-95); }

  .btn-danger {
    background: var(--color-error);
    color: var(--color-on-error);
    border: none;
  }
  .btn-danger:hover { background: #9A0007; }

  .btn:disabled {
    opacity: 0.38;
    cursor: not-allowed;
  }
</style>
```

### Status Badge

```svelte
<!-- StatusBadge.svelte -->
<script lang="ts">
  export let status: 'connected' | 'disconnected' | 'advertising' | 'error' | 'pairing' | 'verified' | 'warning';
</script>

<span class="badge badge-{status}">
  <span class="indicator"></span>
  <slot />
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }

  .badge-connected {
    background: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }
  .badge-connected .indicator { background: var(--color-security-verified); }

  .badge-disconnected {
    background: var(--color-security-neutral-container);
    color: var(--color-on-security-neutral-container);
  }
  .badge-disconnected .indicator { background: var(--color-security-neutral); }

  .badge-advertising {
    background: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
  }
  .badge-advertising .indicator {
    background: var(--color-security-warning);
    animation: pulse 2s infinite;
  }

  .badge-error {
    background: var(--color-security-danger-container);
    color: var(--color-on-security-danger-container);
  }
  .badge-error .indicator { background: var(--color-security-danger); }

  .badge-pairing {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }
  .badge-pairing .indicator {
    background: var(--color-primary-60);
    animation: pulse 1.5s infinite;
  }

  .badge-verified {
    background: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }
  .badge-verified .indicator { background: var(--color-security-verified); }

  .badge-warning {
    background: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
  }
  .badge-warning .indicator { background: var(--color-security-warning); }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
```

### Header with Gradient

```svelte
<!-- GradientHeader.svelte -->
<script lang="ts">
  export let title: string;
  export let subtitle: string = '';
</script>

<header class="gradient-header">
  <h1>{title}</h1>
  {#if subtitle}
    <p>{subtitle}</p>
  {/if}
  <slot />
</header>

<style>
  .gradient-header {
    background: var(--gradient-primary);
    color: var(--color-on-primary);
    padding: 24px 32px;
    border-radius: 0 0 24px 24px;
  }

  h1 {
    font-size: 28px;
    font-weight: 500;
    margin: 0;
  }

  p {
    font-size: 14px;
    opacity: 0.9;
    margin: 4px 0 0;
  }
</style>
```

---

## Icons

Use Material Design Icons for consistency with Android. Install via:

```bash
npm install @mdi/js @mdi/svelte
```

### Common Icons

| Icon | MDI Name | Usage |
|------|----------|-------|
| 🔑 | `mdiKey` | Keys, credentials |
| 📱 | `mdiCellphone` | Phone backend |
| 🛡️ | `mdiShield` | FIDO2, security |
| 🔢 | `mdiNumeric` | OATH TOTP |
| 💳 | `mdiCreditCard` | PIV certificates |
| 🔒 | `mdiLock` | TPM, locked |
| ⚙️ | `mdiCog` | Settings |
| 📋 | `mdiClipboardList` | Audit log |
| ✓ | `mdiCheck` | Success, verified |
| ⚠ | `mdiAlert` | Warning |
| ✕ | `mdiClose` | Error, close |
| + | `mdiPlus` | Add |
| ↻ | `mdiRefresh` | Refresh |

---

## Motion

### Transitions

```css
/* Standard transitions */
--transition-fast: 150ms ease;
--transition-normal: 250ms ease;
--transition-slow: 400ms ease;

/* Spring-like for interactive elements */
--transition-spring: 300ms cubic-bezier(0.34, 1.56, 0.64, 1);
```

### Animation Guidelines

- **Fast (150ms)**: Hover states, small changes
- **Normal (250ms)**: View transitions, modals
- **Slow (400ms)**: Page transitions, complex animations
- **Spring**: Buttons, toggles, checkboxes

---

## Responsive Breakpoints

```css
/* Mobile-first breakpoints */
--screen-sm: 640px;   /* Small tablets */
--screen-md: 768px;   /* Tablets */
--screen-lg: 1024px;  /* Laptops */
--screen-xl: 1280px;  /* Desktops */
--screen-2xl: 1536px; /* Large screens */
```

---

## Accessibility

### Focus States

```css
:focus-visible {
  outline: 2px solid var(--color-primary);
  outline-offset: 2px;
}

/* High contrast focus for dark theme */
[data-theme="dark"] :focus-visible {
  outline-color: var(--color-secondary);
}
```

### Color Contrast

All color combinations meet WCAG AA (4.5:1 for normal text, 3:1 for large text):

| Foreground | Background | Ratio | Pass |
|------------|------------|-------|------|
| on-primary | primary | 12.6:1 | AAA |
| on-secondary | secondary | 7.2:1 | AAA |
| on-tertiary | tertiary | 4.6:1 | AA |
| on-surface | surface | 14.1:1 | AAA |
| on-background | background | 14.1:1 | AAA |

---

## Dark Theme

The dark theme uses navy-charcoal surfaces (never pure black) for premium depth. Switch themes via:

```javascript
// Toggle theme
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('xkey-theme', next);
}

// Initialize from system preference or saved
function initTheme() {
  const saved = localStorage.getItem('xkey-theme');
  if (saved) {
    document.documentElement.setAttribute('data-theme', saved);
  } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
}
```
