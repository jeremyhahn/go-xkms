<script lang="ts">
  interface Props {
    label: string;
    value: string | number;
    hint?: string;
  }
  let { label, value, hint }: Props = $props();
</script>

<div class="card bg-base-200 shadow-sm">
  <div class="card-body p-4">
    <div class="text-xs uppercase tracking-wide text-base-content/60">{label}</div>
    <div class="text-2xl font-semibold">{value}</div>
    {#if hint}
      <div class="text-xs text-base-content/60">{hint}</div>
    {/if}
  </div>
</div>
