# Component Library

Shared Svelte components in `web/packages/shared/src/components/`. All components support dark mode via TailwindCSS `dark:` variants.

## Components

### Button

Styled button with loading state.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `variant` | `'primary' \| 'secondary' \| 'danger' \| 'ghost'` | `'primary'` | Visual style |
| `size` | `'sm' \| 'md' \| 'lg'` | `'md'` | Button size |
| `disabled` | `boolean` | `false` | Disabled state |
| `loading` | `boolean` | `false` | Shows spinner and disables button |
| `type` | `'button' \| 'submit' \| 'reset'` | `'button'` | HTML button type |

```svelte
<Button variant="danger" loading={submitting} on:click={handleRevoke}>
  Revoke Certificate
</Button>
```

### Card

Container with optional title, subtitle, and footer slot.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `title` | `string` | `''` | Card header title |
| `subtitle` | `string` | `''` | Card header subtitle |

Slots: default (body), `footer`.

```svelte
<Card title="Certificate Details" subtitle="Serial: ABC123">
  <p>Content here</p>
  <div slot="footer"><Button>Save</Button></div>
</Card>
```

### DataTable

Sortable, paginated data table with loading and empty states.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `columns` | `Column[]` | `[]` | Column definitions |
| `data` | `any[]` | `[]` | Row data |
| `loading` | `boolean` | `false` | Show loading spinner |
| `emptyMessage` | `string` | `'No data available'` | Empty state text |
| `sortKey` | `string` | `''` | Active sort column |
| `sortDirection` | `'asc' \| 'desc'` | `'asc'` | Sort direction |
| `currentPage` | `number` | `1` | Current page |
| `totalPages` | `number` | `1` | Total pages |
| `showPagination` | `boolean` | `false` | Show pagination controls |

Column interface:
```typescript
interface Column {
  key: string;        // Row property name
  label: string;      // Header text
  sortable?: boolean; // Enable column sorting
  width?: string;     // CSS width
  align?: 'left' | 'center' | 'right';
  render?: (value: any, row: any) => string;  // Custom cell renderer
}
```

### FormField

Form field wrapper with label, error, and hint text.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `label` | `string` | `''` | Field label |
| `error` | `string` | `''` | Error message (shown in red) |
| `required` | `boolean` | `false` | Show required asterisk |
| `hint` | `string` | `''` | Help text (hidden when error is set) |
| `id` | `string` | `''` | Associates label with input via `for` |

```svelte
<FormField label="Domain" required error={domainError} hint="e.g., example.com">
  <input id="domain" bind:value={domain} />
</FormField>
```

### Modal

Dialog overlay with backdrop, close button, and keyboard support (Escape to close).

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `open` | `boolean` | `false` | Visibility toggle |
| `title` | `string` | `''` | Modal header title |
| `size` | `'sm' \| 'md' \| 'lg' \| 'xl'` | `'md'` | Width constraint |
| `closeable` | `boolean` | `true` | Show close button, allow Escape/backdrop close |

Events: `close`. Slots: default (body), `footer`.

### Sidebar

Collapsible navigation sidebar with icon support and theme toggle.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `items` | `NavItem[]` | `[]` | Navigation items |
| `activeView` | `string` | `''` | Currently active view key |
| `collapsed` | `boolean` | `false` | Collapsed state |
| `title` | `string` | `'Trusted CA'` | Sidebar header title |

Events: `navigate` (emits view string).

### StatusBadge

Colored pill badge based on status string.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `status` | `string` | `''` | Status value |

Color mapping:
- **Green**: valid, active, issued, ready
- **Red**: expired, revoked, deactivated, deleted, invalid
- **Blue**: pending, processing
- **Amber**: pending-rotation, expiring, suspended, unused

### Tabs

Tab navigation with content slot.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `tabs` | `Tab[]` | `[]` | Tab definitions: `{ label, value }` |
| `activeTab` | `string` | `''` | Active tab value |

Events: `change` (emits tab value string).

### LoadingSpinner

Animated SVG spinner.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `size` | `'sm' \| 'md' \| 'lg'` | `'md'` | Spinner size (16/24/40px) |
| `color` | `string` | `''` | Custom color class |

### Toast

Notification container. Renders all notifications from the `notifications` store. Positioned at bottom-right with slide-in animation.

No props -- reads from the store directly. Include once in each app's root component:

```svelte
<Toast />
```

### Pagination

Page navigation with previous/next buttons and numbered pages with ellipsis.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `currentPage` | `number` | `1` | Active page |
| `totalPages` | `number` | `1` | Total page count |

Events: `pageChange` (emits page number).
