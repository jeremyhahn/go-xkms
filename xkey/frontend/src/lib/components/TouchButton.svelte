<script lang="ts">
  import Icon from './Icon.svelte';
  import { mdiFingerprint } from '$lib/utils/icons';

  export let pending: boolean = false;
  export let onTouch: (() => void | Promise<void>) | null = null;

  let pressing = false;

  function handleClick(): void {
    if (!pending || !onTouch) return;
    pressing = true;
    const result = onTouch();
    if (result && typeof (result as Promise<void>).then === 'function') {
      (result as Promise<void>).finally(() => { pressing = false; });
    } else {
      pressing = false;
    }
  }
</script>

<button
    class="touch-button"
    class:touch-pending={pending}
    class:touch-pressing={pressing}
    on:click={handleClick}
    aria-label={pending ? 'Touch required - click to approve' : 'No touch pending'}
    title={pending ? 'Click to approve user presence verification' : 'User presence verification (waiting for request)'}
    disabled={!pending}
    data-testid="touch-button"
>
  <span class="icon-wrapper">
    <Icon path={mdiFingerprint} size={pending ? 24 : 22} />
    {#if pending}
      <span class="sonar-ring sonar-1"></span>
      <span class="sonar-ring sonar-2"></span>
    {/if}
  </span>
  {#if pending}
    <span class="touch-label">Touch</span>
  {/if}
</button>

<style>
  .touch-button {
    position: relative;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: default;
    opacity: 0.5;
    transition: all 0.2s ease;
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
    -webkit-user-select: none;
    user-select: none;
  }

  .touch-button:disabled {
    cursor: default;
  }

  .touch-button.touch-pending {
    opacity: 1;
    cursor: pointer;
    color: var(--color-primary);
    border-color: var(--color-primary);
    background: var(--color-primary-95);
    animation: touch-breathe 1.8s ease-in-out infinite, touch-enter 400ms cubic-bezier(0.34, 1.56, 0.64, 1);
    box-shadow:
      0 0 10px 3px rgba(var(--color-primary-rgb, 103, 80, 164), 0.3),
      0 0 24px 8px rgba(var(--color-primary-rgb, 103, 80, 164), 0.12);
  }

  :global([data-theme="dark"]) .touch-button.touch-pending {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
    border-color: var(--color-primary);
    box-shadow:
      0 0 12px 4px rgba(var(--color-primary-rgb, 103, 80, 164), 0.4),
      0 0 28px 10px rgba(var(--color-primary-rgb, 103, 80, 164), 0.18);
  }

  .touch-button.touch-pending:hover {
    background: var(--color-primary-90);
    transform: scale(1.08);
    box-shadow:
      0 0 14px 5px rgba(var(--color-primary-rgb, 103, 80, 164), 0.4),
      0 0 32px 12px rgba(var(--color-primary-rgb, 103, 80, 164), 0.18);
  }

  :global([data-theme="dark"]) .touch-button.touch-pending:hover {
    background: var(--color-primary-container);
    filter: brightness(1.15);
    box-shadow:
      0 0 16px 6px rgba(var(--color-primary-rgb, 103, 80, 164), 0.5),
      0 0 36px 14px rgba(var(--color-primary-rgb, 103, 80, 164), 0.22);
  }

  .touch-button.touch-pending:active,
  .touch-button.touch-pressing {
    transform: scale(0.95);
    box-shadow:
      0 0 4px 1px rgba(var(--color-primary-rgb, 103, 80, 164), 0.4);
    transition: transform 0.1s ease, box-shadow 0.1s ease;
  }

  .icon-wrapper {
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  /* Two staggered sonar rings that expand outward */
  .sonar-ring {
    position: absolute;
    top: 50%;
    left: 50%;
    width: 28px;
    height: 28px;
    transform: translate(-50%, -50%);
    border-radius: 50%;
    border: 2px solid rgba(var(--color-primary-rgb, 103, 80, 164), 0.6);
    pointer-events: none;
  }

  .sonar-1 {
    animation: sonar-expand 2s ease-out infinite;
  }

  .sonar-2 {
    animation: sonar-expand 2s ease-out 1s infinite;
  }

  .touch-label {
    animation: fade-in 200ms ease;
  }

  @keyframes touch-enter {
    from { transform: scale(0.85); opacity: 0.5; }
    to { transform: scale(1); opacity: 1; }
  }

  @keyframes touch-breathe {
    0%, 100% {
      box-shadow:
        0 0 10px 3px rgba(var(--color-primary-rgb, 103, 80, 164), 0.3),
        0 0 24px 8px rgba(var(--color-primary-rgb, 103, 80, 164), 0.12);
    }
    50% {
      box-shadow:
        0 0 18px 8px rgba(var(--color-primary-rgb, 103, 80, 164), 0.45),
        0 0 36px 14px rgba(var(--color-primary-rgb, 103, 80, 164), 0.2);
    }
  }

  @keyframes sonar-expand {
    0% {
      transform: translate(-50%, -50%) scale(1);
      opacity: 0.7;
    }
    70% {
      transform: translate(-50%, -50%) scale(2);
      opacity: 0;
    }
    100% {
      transform: translate(-50%, -50%) scale(2);
      opacity: 0;
    }
  }

  @keyframes fade-in {
    from { opacity: 0; transform: translateX(-4px); }
    to { opacity: 1; transform: translateX(0); }
  }
</style>
