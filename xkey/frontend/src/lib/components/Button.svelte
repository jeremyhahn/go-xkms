<script lang="ts">
  import Icon from './Icon.svelte';

  export let variant: 'primary' | 'secondary' | 'tertiary' | 'outline' | 'text' | 'danger' = 'primary';
  export let size: 'sm' | 'md' | 'lg' = 'md';
  export let disabled: boolean = false;
  export let loading: boolean = false;
  export let icon: string = '';
  export let type: 'button' | 'submit' | 'reset' = 'button';
  export let fullWidth: boolean = false;

  const sizeClasses: Record<string, string> = {
    sm: 'btn-sm',
    md: 'btn-md',
    lg: 'btn-lg',
  };
</script>

<button
  class="btn btn-{variant} {sizeClasses[size]}"
  class:btn-full={fullWidth}
  class:btn-disabled={disabled || loading}
  {type}
  disabled={disabled || loading}
  on:click
  on:keydown
  {...$$restProps}
>
  {#if loading}
    <svg class="btn-spinner" viewBox="0 0 24 24" width="18" height="18">
      <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="31.4 31.4" />
    </svg>
  {:else if icon}
    <Icon path={icon} size={size === 'sm' ? 16 : size === 'lg' ? 22 : 18} />
  {/if}
  <span class="btn-label"><slot /></span>
</button>

<style>
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    border: none;
    border-radius: var(--radius-xl);
    font-family: var(--font-sans);
    font-weight: 500;
    letter-spacing: 0.1px;
    cursor: pointer;
    transition: background-color var(--transition-fast),
                box-shadow var(--transition-fast),
                transform var(--transition-fast),
                opacity var(--transition-fast);
    position: relative;
    overflow: hidden;
    white-space: nowrap;
    user-select: none;
    -webkit-user-select: none;
  }

  .btn::after {
    content: '';
    position: absolute;
    inset: 0;
    background: currentColor;
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  .btn:hover::after {
    opacity: 0.08;
  }

  .btn:active {
    transform: scale(0.98);
  }

  .btn:active::after {
    opacity: 0.12;
  }

  .btn-sm {
    height: 32px;
    padding: 0 16px;
    font-size: 12px;
    line-height: 16px;
  }

  .btn-md {
    height: 40px;
    padding: 0 24px;
    font-size: 14px;
    line-height: 20px;
  }

  .btn-lg {
    height: 48px;
    padding: 0 32px;
    font-size: 16px;
    line-height: 24px;
  }

  .btn-full {
    width: 100%;
  }

  /* Variants */
  .btn-primary {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
    box-shadow: var(--shadow-sm);
  }
  .btn-primary:hover {
    box-shadow: var(--shadow-md);
  }

  .btn-secondary {
    background-color: var(--color-secondary);
    color: var(--color-on-secondary);
    box-shadow: var(--shadow-sm);
  }
  .btn-secondary:hover {
    box-shadow: var(--shadow-md);
  }

  .btn-tertiary {
    background-color: var(--color-tertiary);
    color: var(--color-on-tertiary);
    box-shadow: var(--shadow-sm);
  }
  .btn-tertiary:hover {
    box-shadow: var(--shadow-md);
  }

  .btn-outline {
    background-color: transparent;
    color: var(--color-primary);
    border: 1px solid var(--color-outline);
  }
  .btn-outline:hover {
    background-color: var(--color-primary-95);
  }
  :global([data-theme="dark"]) .btn-outline:hover {
    background-color: var(--color-surface-container-high);
  }

  .btn-text {
    background-color: transparent;
    color: var(--color-primary);
    padding-left: 12px;
    padding-right: 12px;
  }

  .btn-danger {
    background-color: var(--color-error);
    color: var(--color-on-error);
    box-shadow: var(--shadow-sm);
  }
  .btn-danger:hover {
    box-shadow: var(--shadow-md);
  }

  .btn-disabled {
    opacity: 0.38;
    cursor: not-allowed;
    pointer-events: none;
  }

  .btn-label {
    position: relative;
    z-index: 1;
  }

  .btn-spinner {
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
