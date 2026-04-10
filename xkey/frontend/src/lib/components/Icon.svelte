<script lang="ts">
  export let path: string;
  export let size: number = 24;
  export let color: string = 'currentColor';
  export let title: string = '';
</script>

<svg
  viewBox="0 0 24 24"
  width={size}
  height={size}
  fill={color}
  class="icon"
  aria-hidden={title ? 'false' : 'true'}
  role={title ? 'img' : undefined}
>
  {#if title}
    <title>{title}</title>
  {/if}
  <path d={path} />
</svg>

<style>
  .icon {
    display: inline-block;
    vertical-align: middle;
    flex-shrink: 0;
  }
</style>
