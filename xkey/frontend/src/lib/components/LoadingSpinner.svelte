<script lang="ts">
  export let size: number = 40;
</script>

<div class="spinner-wrapper" style="width: {size}px; height: {size}px">
  <svg viewBox="0 0 50 50" class="spinner" width={size} height={size}>
    <circle
      cx="25"
      cy="25"
      r="20"
      fill="none"
      stroke="var(--color-primary)"
      stroke-width="4"
      stroke-linecap="round"
      stroke-dasharray="80 120"
    />
  </svg>
</div>

<style>
  .spinner-wrapper {
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .spinner {
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
