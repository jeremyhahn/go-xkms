<script lang="ts">
  export let sticky: boolean = false;
</script>

<div class="view-toolbar" class:view-toolbar-sticky={sticky}>
  <slot />
</div>

<style>
  .view-toolbar {
    display: flex;
    align-items: center;
    gap: 8px;
    min-height: 56px;
    padding: 8px 24px;
    background-color: var(--color-surface-container-lowest);
    border-bottom: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
    flex-wrap: wrap;
  }

  .view-toolbar-sticky {
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .view-toolbar :global(.toolbar-spacer) {
    flex: 1;
  }
</style>
