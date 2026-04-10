<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let checked: boolean = false;
  export let label: string = '';
  export let disabled: boolean = false;
  export let onChange: (checked: boolean) => void = () => {};

  const dispatch = createEventDispatcher<{ change: boolean }>();

  function handleToggle(): void {
    if (disabled) return;
    checked = !checked;
    onChange(checked);
    dispatch('change', checked);
  }
</script>

<label class="toggle-wrapper" class:toggle-disabled={disabled} {...$$restProps}>
  <button
    class="toggle-track"
    class:toggle-on={checked}
    role="switch"
    aria-checked={checked}
    {disabled}
    on:click={handleToggle}
  >
    <span class="toggle-thumb"></span>
  </button>
  {#if label}
    <span class="toggle-label text-body-medium">{label}</span>
  {/if}
</label>

<style>
  .toggle-wrapper {
    display: inline-flex;
    align-items: center;
    gap: 12px;
    cursor: pointer;
  }

  .toggle-disabled {
    opacity: 0.38;
    cursor: not-allowed;
  }

  .toggle-track {
    position: relative;
    width: 52px;
    height: 32px;
    border-radius: 16px;
    border: 2px solid var(--color-outline);
    background-color: var(--color-surface-variant);
    cursor: pointer;
    padding: 0;
    transition: background-color var(--transition-normal),
                border-color var(--transition-normal);
    flex-shrink: 0;
  }

  .toggle-track.toggle-on {
    background-color: var(--color-primary);
    border-color: var(--color-primary);
  }

  .toggle-thumb {
    position: absolute;
    top: 4px;
    left: 4px;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    background-color: var(--color-outline);
    transition: transform var(--transition-spring),
                background-color var(--transition-normal),
                width var(--transition-fast),
                height var(--transition-fast);
  }

  .toggle-on .toggle-thumb {
    transform: translateX(20px);
    background-color: var(--color-on-primary);
  }

  .toggle-track:active .toggle-thumb {
    width: 24px;
    height: 24px;
    top: 2px;
    left: 2px;
  }

  .toggle-on:active .toggle-thumb {
    transform: translateX(16px);
  }

  .toggle-label {
    color: var(--color-on-surface);
    user-select: none;
    -webkit-user-select: none;
  }
</style>
