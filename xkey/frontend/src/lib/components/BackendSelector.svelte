<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Icon from '$lib/components/Icon.svelte';
  import { mdiFilter } from '$lib/utils/icons';
  import { getBackendIcon } from '$lib/utils/backends';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { BackendBackendInfo } from '$lib/api/backend';

  /** Optional capability filter (e.g., 'signing', 'fido2', 'piv', 'oath', 'passwords'). */
  export let capability: string = '';

  /** Currently selected backend ID, or 'all'. */
  export let selected: string = 'all';

  /** Show "All Backends" chip. Set to false for dialog selectors. */
  export let showAll: boolean = true;

  /** Only show connected backends. */
  export let connectedOnly: boolean = false;

  /** Compact mode omits icons and uses smaller chips. */
  export let compact: boolean = false;

  const dispatch = createEventDispatcher<{ change: string }>();

  let backends: BackendBackendInfo[] = [];

  export async function refresh(): Promise<void> {
    if (!isWailsAvailable()) {
      console.debug('[BackendSelector] Wails not available, skipping refresh');
      return;
    }
    const list = await callBackend<BackendBackendInfo[]>('AdminService', 'ListBackends');
    if (!list) {
      console.debug('[BackendSelector] ListBackends returned null/empty');
      return;
    }

    console.debug('[BackendSelector] ListBackends returned', list.length, 'backends, filtering by capability:', capability);
    backends = list.filter(b => {
      if (!b.enabled) return false;
      if (connectedOnly && !b.connected) return false;
      if (capability && b.capabilities) {
        const capKey = capability as keyof typeof b.capabilities;
        if (capKey in b.capabilities && !b.capabilities[capKey]) {
          console.debug('[BackendSelector] Filtered out', b.id, 'missing capability', capability);
          return false;
        }
      }
      return true;
    });
    console.debug('[BackendSelector] After filter:', backends.length, 'backends', backends.map(b => b.id));

    // Auto-select when "All" is hidden: pick the first backend if nothing
    // is selected, or if the current selection is no longer in the list.
    if (!showAll && backends.length > 0) {
      const valid = backends.some(b => b.id === selected);
      if (!valid || selected === '' || selected === 'all') {
        select(backends[0].id);
      }
    }
  }

  function select(id: string): void {
    selected = id;
    dispatch('change', id);
  }

  /** Returns the filtered backends for external access. */
  export function getBackends(): BackendBackendInfo[] {
    return backends;
  }

  // Auto-load on mount via reactive statement
  $: if (capability !== undefined) {
    refresh();
  }
</script>

<div class="backend-selector" class:compact {...$$restProps}>
  <Icon path={mdiFilter} size={compact ? 14 : 18} />
  {#if showAll}
    <button
      class="filter-chip"
      class:active={selected === 'all'}
      on:click={() => select('all')}
    >
      All Backends
    </button>
  {/if}
  {#each backends as b}
    <button
      class="filter-chip"
      class:active={selected === b.id}
      on:click={() => select(b.id)}
    >
      {#if !compact}
        <Icon path={getBackendIcon(b.type)} size={14} />
      {/if}
      {b.display_name || b.id}
      {#if !b.connected}
        <span class="offline-dot" title="Disconnected"></span>
      {/if}
    </button>
  {/each}
</div>

<style>
  .backend-selector {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
    color: var(--color-on-surface-variant);
  }

  .filter-chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 12px;
    border-radius: var(--radius-full);
    border: 1px solid var(--color-outline-variant);
    background: transparent;
    color: var(--color-on-surface-variant);
    font-size: 13px;
    font-family: var(--font-sans);
    cursor: pointer;
    transition: all var(--transition-fast);
    white-space: nowrap;
  }

  .filter-chip:hover {
    background-color: var(--color-surface-container);
    border-color: var(--color-outline);
  }

  .filter-chip.active {
    background-color: var(--color-secondary-container);
    color: var(--color-on-secondary-container);
    border-color: var(--color-secondary-container);
    font-weight: 500;
  }

  .compact .filter-chip {
    padding: 2px 8px;
    font-size: 12px;
  }

  .offline-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background-color: var(--color-error);
    flex-shrink: 0;
  }
</style>
