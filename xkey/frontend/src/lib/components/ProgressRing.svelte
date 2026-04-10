<script lang="ts">
  export let progress: number = 0;
  export let size: number = 48;
  export let strokeWidth: number = 4;

  $: radius = (size - strokeWidth) / 2;
  $: circumference = 2 * Math.PI * radius;
  $: offset = circumference * (1 - Math.max(0, Math.min(1, progress)));
</script>

<svg
  class="progress-ring"
  width={size}
  height={size}
  viewBox="0 0 {size} {size}"
>
  <circle
    class="progress-track"
    cx={size / 2}
    cy={size / 2}
    r={radius}
    fill="none"
    stroke="var(--color-surface-variant)"
    stroke-width={strokeWidth}
  />
  <circle
    class="progress-fill"
    cx={size / 2}
    cy={size / 2}
    r={radius}
    fill="none"
    stroke="var(--color-primary)"
    stroke-width={strokeWidth}
    stroke-linecap="round"
    stroke-dasharray={circumference}
    stroke-dashoffset={offset}
    transform="rotate(-90 {size / 2} {size / 2})"
  />
  <slot />
</svg>

<style>
  .progress-ring {
    display: inline-block;
  }

  .progress-fill {
    transition: stroke-dashoffset 250ms ease;
  }
</style>
