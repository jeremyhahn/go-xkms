<script lang="ts">
  export let tabs: Array<{ id: string; label: string }> = [];
  export let activeTab: string = '';
  export let onChange: (id: string) => void = () => {};

  function select(id: string): void {
    activeTab = id;
    onChange(id);
  }
</script>

<div class="tabs" role="tablist">
  {#each tabs as tab (tab.id)}
    <button
      class="tab text-label-large"
      class:tab-active={activeTab === tab.id}
      role="tab"
      aria-selected={activeTab === tab.id}
      on:click={() => select(tab.id)}
      data-testid="tab-{tab.id}"
    >
      {tab.label}
      {#if activeTab === tab.id}
        <span class="tab-indicator"></span>
      {/if}
    </button>
  {/each}
</div>

<style>
  .tabs {
    display: flex;
    border-bottom: 1px solid var(--color-outline-variant);
    gap: 0;
    overflow-x: auto;
  }

  .tab {
    position: relative;
    padding: 12px 24px;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    white-space: nowrap;
    transition: color var(--transition-fast),
                background-color var(--transition-fast);
    font-family: var(--font-sans);
  }

  .tab:hover {
    color: var(--color-on-surface);
    background-color: var(--color-surface-container);
  }

  .tab-active {
    color: var(--color-primary);
  }

  .tab-indicator {
    position: absolute;
    bottom: 0;
    left: 8px;
    right: 8px;
    height: 3px;
    background-color: var(--color-primary);
    border-radius: 3px 3px 0 0;
    animation: scale-in 200ms ease;
  }

  @keyframes scale-in {
    from { transform: scaleX(0); }
    to { transform: scaleX(1); }
  }
</style>
