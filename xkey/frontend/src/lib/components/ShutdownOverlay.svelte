<script lang="ts">
  import { shuttingDown } from '$lib/stores/events';
</script>

{#if $shuttingDown}
  <div class="shutdown-overlay">
    <div class="shutdown-content">
      <div class="shutdown-spinner"></div>
      <h2>Shutting Down</h2>
      <p>Securing data and closing connections...</p>
    </div>
  </div>
{/if}

<style>
  .shutdown-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.85);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 99999;
  }

  .shutdown-content {
    text-align: center;
    color: white;
  }

  .shutdown-content h2 {
    margin: 1rem 0 0.5rem;
    font-size: 1.5rem;
    font-weight: 600;
  }

  .shutdown-content p {
    margin: 0;
    opacity: 0.7;
    font-size: 0.9rem;
  }

  .shutdown-spinner {
    width: 48px;
    height: 48px;
    border: 4px solid rgba(255, 255, 255, 0.2);
    border-top-color: white;
    border-radius: 50%;
    margin: 0 auto;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
