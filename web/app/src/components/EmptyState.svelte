<script lang="ts">
  interface Props {
    title: string;
    message?: string;
  }
  let { title, message }: Props = $props();
</script>

<div class="text-center py-12 text-base-content/60">
  <div class="text-lg font-medium">{title}</div>
  {#if message}
    <p class="text-sm mt-1">{message}</p>
  {/if}
</div>
