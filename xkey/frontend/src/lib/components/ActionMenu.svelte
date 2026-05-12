<script lang="ts">
  import { tick } from 'svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { mdiDotsVertical } from '$lib/utils/icons';
  import type { ActionItem, PrimaryAction } from './ActionMenu.types';

  /** Svelte action: moves the element to document.body so it escapes any
   *  ancestor that creates a stacking context or clips overflow. A card
   *  with `transform: translateY(-1px)` on hover, for example, would
   *  otherwise make `position: fixed` behave like `position: absolute`
   *  anchored to that card. */
  function portal(node: HTMLElement) {
    document.body.appendChild(node);
    return {
      destroy(): void {
        if (node.parentNode) node.parentNode.removeChild(node);
      },
    };
  }

  export let primaryAction: PrimaryAction | null = null;
  export let actions: ActionItem[] = [];

  let open = false;
  let menuEl: HTMLElement;
  let kebabEl: HTMLButtonElement;
  let itemEls: HTMLButtonElement[] = [];
  let menuTop = 0;
  let menuRight = 0;

  /** Compute menu position from the kebab's viewport rect so the popover
   *  can use `position: fixed` and escape any ancestor `overflow` clipping. */
  function positionMenu(): void {
    if (!kebabEl) return;
    const rect = kebabEl.getBoundingClientRect();
    menuTop = rect.bottom + 6;
    menuRight = Math.max(8, window.innerWidth - rect.right);
  }


  /** Focusable item indices (excludes dividers). */
  $: focusableIndices = actions
    .map((a, i) => (!a.divider ? i : -1))
    .filter(i => i !== -1);

  function openMenu(): void {
    positionMenu();
    open = true;
    tick().then(() => {
      const first = itemEls[focusableIndices[0]];
      if (first) first.focus();
    });
  }

  function closeMenu(): void {
    open = false;
  }

  /** Close when clicking outside both the kebab and the (portal'd) menu.
   *  Uses pointerdown capture so it fires before element click handlers. */
  function handleDocPointer(e: PointerEvent): void {
    if (!open) return;
    const target = e.target as Node | null;
    if (!target) return;
    if (kebabEl?.contains(target)) return;
    if (menuEl?.contains(target)) return;
    open = false;
  }

  function handleItemClick(item: ActionItem): void {
    closeMenu();
    item.onClick?.();
  }

  function handleKebabKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openMenu();
    }
  }

  function handleMenuKeydown(e: KeyboardEvent): void {
    if (e.key === 'Escape') {
      e.preventDefault();
      closeMenu();
      return;
    }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;

    e.preventDefault();
    const current = document.activeElement;
    const focused = focusableIndices.findIndex(i => itemEls[i] === current);

    let next: number;
    if (e.key === 'ArrowDown') {
      next = focused < focusableIndices.length - 1 ? focused + 1 : 0;
    } else {
      next = focused > 0 ? focused - 1 : focusableIndices.length - 1;
    }

    itemEls[focusableIndices[next]]?.focus();
  }
</script>

<svelte:window
  on:scroll|capture={() => open && (open = false)}
  on:resize={() => open && (open = false)}
  on:pointerdown|capture={handleDocPointer}
/>

<!-- svelte-ignore a11y-no-static-element-interactions -->
<div class="action-menu-root">
  <!-- Primary action button (optional) -->
  {#if primaryAction}
    <Button
      variant={primaryAction.variant ?? 'primary'}
      size="sm"
      icon={primaryAction.icon ?? ''}
      loading={primaryAction.loading ?? false}
      on:click={primaryAction.onClick}
      data-testid={primaryAction.testid}
    >
      {primaryAction.label}
    </Button>
  {/if}

  <!-- Kebab overflow trigger -->
  <button
    bind:this={kebabEl}
    class="kebab-btn"
    type="button"
    aria-haspopup="menu"
    aria-expanded={open}
    aria-label="More actions"
    on:click={openMenu}
    on:keydown={handleKebabKeydown}
    data-testid="action-menu-kebab"
  >
    <Icon path={mdiDotsVertical} size={20} />
  </button>

  <!-- Floating overflow menu. Portal'd to <body> so it escapes any
       ancestor transform / overflow that would otherwise clip it or
       re-anchor its position:fixed. -->
  {#if open}
    <div
      class="menu-popover"
      role="menu"
      aria-label="Actions"
      tabindex="-1"
      bind:this={menuEl}
      use:portal
      style="top: {menuTop}px; right: {menuRight}px;"
      on:keydown={handleMenuKeydown}
    >
      {#each actions as item, idx}
        {#if item.divider}
          <div class="menu-divider" role="separator" aria-hidden="true"></div>
        {:else}
          <button
            class="menu-item"
            class:destructive={item.destructive}
            role="menuitem"
            type="button"
            bind:this={itemEls[idx]}
            on:click={() => handleItemClick(item)}
            data-testid={item.testid}
          >
            {#if item.icon}
              <span class="menu-item-icon">
                <Icon path={item.icon} size={20} />
              </span>
            {/if}
            <span class="menu-item-label">{item.label}</span>
          </button>
        {/if}
      {/each}
    </div>
  {/if}
</div>

<style>
  .action-menu-root {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }

  /* ── Kebab button ──────────────────────────────────────────── */
  .kebab-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition:
      background-color var(--transition-fast),
      color var(--transition-fast);
    flex-shrink: 0;
  }

  .kebab-btn:hover {
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface);
  }

  .kebab-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }

  /* ── Floating menu ─────────────────────────────────────────── */
  .menu-popover {
    /* position: fixed escapes any ancestor overflow:auto clipping so the
       menu can extend beyond its card/scroll container. Coordinates are
       computed from the kebab's viewport rect in openMenu(). */
    position: fixed;
    /* Very high z-index to stay above sibling cards in grid layouts
       and any other on-page chrome. Modal backdrops sit at 99998+. */
    z-index: 9000;
    min-width: 240px;
    padding: 6px;
    background: var(--color-surface);
    border: 1px solid var(--color-outline-variant);
    border-radius: 12px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);

    /* Entrance animation */
    animation: menu-enter 120ms ease-out both;
  }

  @keyframes menu-enter {
    from {
      opacity: 0;
      transform: translateY(-4px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  /* ── Menu items ────────────────────────────────────────────── */
  .menu-item {
    display: flex;
    align-items: center;
    gap: 12px;
    width: 100%;
    height: 40px;
    padding: 0 12px;
    border: none;
    border-radius: 8px;
    background: transparent;
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    text-align: left;
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }

  .menu-item:hover,
  .menu-item:focus-visible {
    background-color: var(--color-surface-variant);
    outline: none;
  }

  .menu-item.destructive {
    color: var(--color-error);
  }

  .menu-item-icon {
    display: inline-flex;
    align-items: center;
    flex-shrink: 0;
    opacity: 0.85;
  }

  .menu-item.destructive .menu-item-icon {
    color: var(--color-error);
  }

  .menu-item-label {
    flex: 1;
    white-space: nowrap;
  }

  /* ── Divider ───────────────────────────────────────────────── */
  .menu-divider {
    height: 1px;
    margin: 4px 0;
    background-color: var(--color-outline-variant);
  }

  /* ── Dark-theme override ────────────────────────────────────── */
  :global([data-theme="dark"]) .menu-popover {
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  }
</style>
