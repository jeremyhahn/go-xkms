<script lang="ts">
  export let title: string;
  export let subtitle: string = '';
</script>

<div class="gradient-header">
  <div class="header-content">
    <div class="header-text">
      <h1 class="text-headline-medium header-title">{title}</h1>
      {#if subtitle}
        <p class="text-body-large header-subtitle">{subtitle}</p>
      {/if}
    </div>
    <div class="header-info">
      <slot />
    </div>
  </div>
</div>

<style>
  .gradient-header {
    background: var(--gradient-primary);
    padding: 24px 32px;
    border-radius: 0 0 var(--radius-xl) var(--radius-xl);
    position: relative;
    overflow: hidden;
  }

  .gradient-header::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 300px;
    height: 300px;
    border-radius: 50%;
    background: rgba(255, 179, 0, 0.08);
    pointer-events: none;
  }

  .gradient-header::after {
    content: '';
    position: absolute;
    bottom: -30%;
    left: -10%;
    width: 200px;
    height: 200px;
    border-radius: 50%;
    background: rgba(0, 137, 123, 0.06);
    pointer-events: none;
  }

  .header-content {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    position: relative;
    z-index: 1;
  }

  .header-text {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .header-title {
    color: #FFFFFF;
    margin: 0;
    font-weight: 600;
  }

  .header-subtitle {
    color: rgba(255, 255, 255, 0.8);
    margin: 0;
  }

  .header-info {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }
</style>
