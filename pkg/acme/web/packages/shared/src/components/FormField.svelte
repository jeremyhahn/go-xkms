<script lang="ts">
  export let label: string = '';
  export let error: string = '';
  export let required: boolean = false;
  export let hint: string = '';
  export let id: string = '';
</script>

<div class="space-y-1.5" {...$$restProps}>
  {#if label}
    <label
      for={id || undefined}
      class="block text-sm font-medium text-slate-700 dark:text-slate-300"
    >
      {label}
      {#if required}
        <span class="text-red-500" aria-hidden="true">*</span>
      {/if}
    </label>
  {/if}

  <slot />

  {#if error}
    <p class="text-sm text-red-600 dark:text-red-400" role="alert">{error}</p>
  {:else if hint}
    <p class="text-sm text-slate-500 dark:text-slate-400">{hint}</p>
  {/if}
</div>
