<script lang="ts">
  import Icon from './Icon.svelte';
  import Button from './Button.svelte';

  export let icon: string = '';
  export let title: string = '';
  export let description: string = '';
  export let actionLabel: string = '';
  export let onAction: (() => void) | null = null;
</script>

<div class="empty-state" {...$$restProps}>
  {#if icon}
    <div class="empty-icon">
      <Icon path={icon} size={56} />
    </div>
  {/if}
  {#if title}
    <h3 class="text-title-large empty-title">{title}</h3>
  {/if}
  {#if description}
    <p class="text-body-medium empty-description">{description}</p>
  {/if}
  {#if actionLabel && onAction}
    <div class="empty-action">
      <Button variant="primary" on:click={onAction}>{actionLabel}</Button>
    </div>
  {/if}
</div>

<style>
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    padding: 48px 32px;
    gap: 12px;
  }

  .empty-icon {
    color: var(--color-on-surface-variant);
    opacity: 0.5;
    margin-bottom: 8px;
  }

  .empty-title {
    color: var(--color-on-surface);
    margin: 0;
  }

  .empty-description {
    color: var(--color-on-surface-variant);
    margin: 0;
    max-width: 360px;
    line-height: 1.5;
  }

  .empty-action {
    margin-top: 16px;
  }
</style>
