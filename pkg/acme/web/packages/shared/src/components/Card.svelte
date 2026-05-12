<script lang="ts">
  export let title: string = '';
  export let subtitle: string = '';
  // Set noPadding to true when slot content needs full-bleed layout
  // (e.g. accordion lists, tables, or divider rows that should span edge-to-edge).
  export let noPadding: boolean = false;
</script>

<div
  class="rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-800"
  {...$$restProps}
>
  {#if title || subtitle}
    <div class="border-b border-slate-200 px-6 py-4 dark:border-slate-700">
      {#if title}
        <h3 class="text-lg font-semibold text-slate-900 dark:text-slate-100">
          {title}
        </h3>
      {/if}
      {#if subtitle}
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
          {subtitle}
        </p>
      {/if}
    </div>
  {/if}

  <div class={noPadding ? '' : 'px-6 py-4'}>
    <slot />
  </div>

  {#if $$slots.footer}
    <div
      class="border-t border-slate-200 px-6 py-3 dark:border-slate-700"
    >
      <slot name="footer" />
    </div>
  {/if}
</div>
