<script lang="ts">
  /**
   * SourceBadge renders a small, muted pill labelling where a read-only item
   * came from (ssh-agent, a local file, ~/.ssh/config, ...). Styled after the
   * `.read-only-badge` pattern in PasswordDetailPanel.svelte — this is the
   * shared primitive for that look wherever a local/external source needs a
   * label instead of an editable BackendBadge.
   */
  export let label: string;
  export let variant: 'agent' | 'file' | 'config' = 'file';
</script>

<span class="source-badge source-badge-{variant}" {...$$restProps}>
  {label}
</span>

<style>
  .source-badge {
    display: inline-flex;
    align-items: center;
    font-size: 11px;
    font-weight: 500;
    border-radius: 12px;
    padding: 3px 9px;
    white-space: nowrap;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    vertical-align: middle;
  }

  .source-badge-agent {
    color: var(--color-primary);
    background-color: var(--color-primary-95);
  }

  :global([data-theme="dark"]) .source-badge-agent {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .source-badge-file,
  .source-badge-config {
    color: var(--color-on-surface-variant);
    background-color: var(--color-surface-container);
    border: 1px solid var(--color-outline-variant);
  }
</style>
