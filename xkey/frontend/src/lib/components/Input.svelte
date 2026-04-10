<script lang="ts">
  import Icon from './Icon.svelte';

  export let id: string = '';
  export let label: string = '';
  export let placeholder: string = '';
  export let value: string | number = '';
  export let error: string = '';
  export let helperText: string = '';
  export let icon: string = '';
  export let type: string = 'text';
  export let disabled: boolean = false;
  export let readonly: boolean = false;
  export let monospace: boolean = false;

  let focused = false;
  const inputId = id || `input-${Math.random().toString(36).substring(2, 9)}`;
</script>

<div class="input-wrapper" class:input-error={!!error} class:input-focused={focused} class:input-disabled={disabled}>
  {#if label}
    <label class="input-label text-label-medium" for={inputId}>{label}</label>
  {/if}
  <div class="input-container">
    {#if icon}
      <span class="input-icon">
        <Icon path={icon} size={20} />
      </span>
    {/if}
    {#if type === 'password'}
      <input
        id={inputId}
        class="input-field"
        class:font-mono={monospace}
        class:has-icon={!!icon}
        type="password"
        {placeholder}
        {disabled}
        {readonly}
        bind:value
        on:focus={() => (focused = true)}
        on:blur={() => (focused = false)}
        on:blur
        on:input
        on:change
        on:keydown
      />
    {:else if type === 'number'}
      <input
        id={inputId}
        class="input-field"
        class:font-mono={monospace}
        class:has-icon={!!icon}
        type="number"
        {placeholder}
        {disabled}
        {readonly}
        bind:value
        on:focus={() => (focused = true)}
        on:blur={() => (focused = false)}
        on:blur
        on:input
        on:change
        on:keydown
      />
    {:else}
      <input
        id={inputId}
        class="input-field"
        class:font-mono={monospace}
        class:has-icon={!!icon}
        type="text"
        {placeholder}
        {disabled}
        {readonly}
        bind:value
        on:focus={() => (focused = true)}
        on:blur={() => (focused = false)}
        on:blur
        on:input
        on:change
        on:keydown
      />
    {/if}
  </div>
  {#if error}
    <span class="input-error-text text-body-small">{error}</span>
  {:else if helperText}
    <span class="input-helper text-body-small">{helperText}</span>
  {/if}
</div>

<style>
  .input-wrapper {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .input-label {
    color: var(--color-on-surface-variant);
    padding-left: 4px;
  }

  .input-container {
    position: relative;
    display: flex;
    align-items: center;
  }

  .input-icon {
    position: absolute;
    left: 12px;
    color: var(--color-on-surface-variant);
    display: flex;
    pointer-events: none;
    z-index: 1;
  }

  .input-field {
    width: 100%;
    height: 48px;
    padding: 0 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 20px;
    outline: none;
    transition: border-color var(--transition-fast),
                box-shadow var(--transition-fast);
  }

  .input-field.has-icon {
    padding-left: 44px;
  }

  .input-field::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .input-focused .input-field {
    border-color: var(--color-primary);
    box-shadow: 0 0 0 1px var(--color-primary);
  }

  .input-error .input-field {
    border-color: var(--color-error);
  }

  .input-error .input-focused .input-field {
    box-shadow: 0 0 0 1px var(--color-error);
  }

  .input-error .input-label {
    color: var(--color-error);
  }

  .input-error-text {
    color: var(--color-error);
    padding-left: 4px;
  }

  .input-helper {
    color: var(--color-on-surface-variant);
    padding-left: 4px;
  }

  .input-disabled {
    opacity: 0.38;
    pointer-events: none;
  }
</style>
