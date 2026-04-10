<script lang="ts">
  import { slide } from 'svelte/transition';
  import Icon from './Icon.svelte';
  import { mdiChevronRight } from '$lib/utils/icons';

  export let title: string = 'Advanced';
  export let defaultOpen: boolean = false;

  let expanded = defaultOpen;

  function toggle(): void {
    expanded = !expanded;
  }
</script>

<div class="collapsible-section">
  <button
    class="collapsible-header"
    class:expanded
    on:click={toggle}
    aria-expanded={expanded}
    type="button"
  >
    <span class="chevron" class:expanded>
      <Icon path={mdiChevronRight} size={18} />
    </span>
    <span class="title">{title}</span>
  </button>

  {#if expanded}
    <div class="collapsible-content" transition:slide={{ duration: 150 }}>
      <slot />
    </div>
  {/if}
</div>

<style>
  .collapsible-section {
    display: flex;
    flex-direction: column;
  }

  .collapsible-header {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 0;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: color var(--transition-fast);
  }

  .collapsible-header:hover {
    color: var(--color-on-surface);
  }

  .chevron {
    display: flex;
    align-items: center;
    justify-content: center;
    transition: transform 150ms ease;
    transform: rotate(0deg);
  }

  .chevron.expanded {
    transform: rotate(90deg);
  }

  .title {
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .collapsible-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding-top: 8px;
    padding-left: 24px;
  }
</style>
