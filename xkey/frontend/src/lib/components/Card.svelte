<script lang="ts">
  export let variant: 'elevated' | 'outlined' | 'security' | 'gradient' = 'elevated';
  export let padding: 'sm' | 'md' | 'lg' = 'md';
  export let hoverable: boolean = false;

  const paddingMap: Record<string, string> = {
    sm: 'p-3',
    md: 'p-4',
    lg: 'p-6',
  };
</script>

<!-- svelte-ignore a11y-no-noninteractive-tabindex -->
<div
  class="card card-{variant} {paddingMap[padding]}"
  class:card-hoverable={hoverable}
  on:click
  on:keydown
  role={hoverable ? 'button' : undefined}
  tabindex={hoverable ? 0 : undefined}
  {...$$restProps}
>
  <slot />
</div>

<style>
  .card {
    border-radius: var(--radius-lg);
    transition: box-shadow var(--transition-normal),
                transform var(--transition-normal),
                border-color var(--transition-fast);
    position: relative;
  }

  .card-elevated {
    background-color: var(--color-surface-container-low);
    box-shadow: var(--shadow-sm);
  }

  .card-outlined {
    background-color: var(--color-surface);
    border: 1px solid var(--color-outline-variant);
  }

  .card-security {
    background-color: var(--color-surface);
    border: 2px solid var(--color-tertiary);
  }

  .card-gradient {
    background: var(--gradient-primary);
    color: var(--color-on-primary);
  }

  .card-hoverable {
    cursor: pointer;
  }

  .card-hoverable:hover {
    box-shadow: var(--shadow-md);
    transform: translateY(-1px);
  }

  .card-hoverable.card-outlined:hover {
    border-color: var(--color-outline);
  }

  .card-hoverable.card-security:hover {
    border-color: var(--color-tertiary-60);
    box-shadow: 0 4px 12px rgba(0, 137, 123, 0.15);
  }

  .card-hoverable:active {
    transform: translateY(0);
    box-shadow: var(--shadow-sm);
  }
</style>
