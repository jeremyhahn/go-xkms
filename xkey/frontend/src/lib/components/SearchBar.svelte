<script lang="ts">
  import Icon from './Icon.svelte';
  import { mdiMagnify, mdiClose } from '$lib/utils/icons';

  export let placeholder: string = 'Search...';
  export let value: string = '';
  export let onChange: (value: string) => void = () => {};

  function handleInput(e: Event): void {
    const target = e.target as HTMLInputElement;
    value = target.value;
    onChange(value);
  }

  function clear(): void {
    value = '';
    onChange('');
  }
</script>

<div class="search-bar" {...$$restProps}>
  <span class="search-icon">
    <Icon path={mdiMagnify} size={20} />
  </span>
  <input
    class="search-input text-body-medium"
    type="text"
    {placeholder}
    {value}
    on:input={handleInput}
  />
  {#if value}
    <button class="search-clear" on:click={clear} aria-label="Clear search">
      <Icon path={mdiClose} size={18} />
    </button>
  {/if}
</div>

<style>
  .search-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 16px;
    height: 44px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-full);
    border: 1px solid transparent;
    transition: border-color var(--transition-fast),
                background-color var(--transition-fast);
  }

  .search-bar:focus-within {
    border-color: var(--color-primary);
    background-color: var(--color-surface-container-lowest);
  }

  .search-icon {
    color: var(--color-on-surface-variant);
    display: flex;
    flex-shrink: 0;
  }

  .search-input {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--color-on-surface);
    outline: none;
    font-family: var(--font-sans);
    min-width: 0;
  }

  .search-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .search-clear {
    width: 28px;
    height: 28px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background-color var(--transition-fast);
  }

  .search-clear:hover {
    background-color: var(--color-surface-variant);
  }
</style>
