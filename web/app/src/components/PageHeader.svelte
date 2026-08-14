<script lang="ts">
  interface Props {
    title: string;
    subtitle?: string;
    actions?: import("svelte").Snippet;
  }
  let { title, subtitle, actions }: Props = $props();
</script>

<div class="flex items-start justify-between mb-6">
  <div>
    <h1 class="text-2xl font-semibold">{title}</h1>
    {#if subtitle}
      <p class="text-sm text-base-content/70 mt-1">{subtitle}</p>
    {/if}
  </div>
  {#if actions}
    <div class="flex gap-2">{@render actions()}</div>
  {/if}
</div>
