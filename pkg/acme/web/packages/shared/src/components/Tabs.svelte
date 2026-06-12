<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  interface Tab {
    label: string;
    value: string;
  }

  export let tabs: Tab[] = [];
  export let activeTab: string = '';

  const dispatch = createEventDispatcher<{ change: string }>();

  function handleTabClick(value: string) {
    activeTab = value;
    dispatch('change', value);
  }
</script>

<div>
  <div class="border-b border-slate-200 dark:border-slate-700" role="tablist">
    <div class="flex gap-0 -mb-px">
      {#each tabs as tab}
        <button
          role="tab"
          aria-selected={activeTab === tab.value}
          class="px-4 py-2.5 text-sm font-medium border-b-2 transition-colors
                 {activeTab === tab.value
                   ? 'border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400'
                   : 'border-transparent text-slate-500 hover:border-slate-300 hover:text-slate-700 dark:text-slate-400 dark:hover:border-slate-600 dark:hover:text-slate-200'}"
          on:click={() => handleTabClick(tab.value)}
        >
          {tab.label}
        </button>
      {/each}
    </div>
  </div>

  <div class="pt-4" role="tabpanel">
    <slot />
  </div>
</div>
