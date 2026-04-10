<script lang="ts">
  import Icon from './Icon.svelte';
  import { mdiCheckCircle, mdiAlertCircle, mdiCloseCircle, mdiInformation, mdiClose } from '$lib/utils/icons';
  import { notifications, removeNotification } from '$lib/stores/notifications';
  import type { NotificationType } from '$lib/stores/notifications';

  const iconMap: Record<NotificationType, string> = {
    info: mdiInformation,
    success: mdiCheckCircle,
    warning: mdiAlertCircle,
    error: mdiCloseCircle,
  };
</script>

<div class="toast-container" aria-live="polite">
  {#each $notifications as notification (notification.id)}
    <div class="toast toast-{notification.type}" role="alert">
      <div class="toast-icon">
        <Icon path={iconMap[notification.type]} size={20} />
      </div>
      <span class="toast-message text-body-medium">{notification.message}</span>
      <button
        class="toast-dismiss"
        on:click={() => removeNotification(notification.id)}
        aria-label="Dismiss notification"
      >
        <Icon path={mdiClose} size={16} />
      </button>
      <div class="toast-progress" style="transform: scaleX({1 - notification.progress})"></div>
    </div>
  {/each}
</div>

<style>
  .toast-container {
    position: fixed;
    bottom: 24px;
    right: 24px;
    display: flex;
    flex-direction: column-reverse;
    gap: 8px;
    z-index: 2000;
    max-width: 400px;
    pointer-events: none;
  }

  .toast {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-lg);
    animation: slide-in-up 300ms cubic-bezier(0.34, 1.56, 0.64, 1);
    pointer-events: auto;
    position: relative;
    overflow: hidden;
  }

  .toast-icon {
    flex-shrink: 0;
    display: flex;
  }

  .toast-message {
    flex: 1;
    min-width: 0;
  }

  .toast-dismiss {
    flex-shrink: 0;
    width: 28px;
    height: 28px;
    border: none;
    border-radius: 50%;
    background: transparent;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0.7;
    transition: opacity var(--transition-fast);
  }

  .toast-dismiss:hover {
    opacity: 1;
  }

  .toast-progress {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 3px;
    transform-origin: left;
    transition: transform 50ms linear;
  }

  .toast-info {
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface);
  }
  .toast-info .toast-icon { color: var(--color-primary); }
  .toast-info .toast-progress { background-color: var(--color-primary); }
  .toast-info .toast-dismiss { color: var(--color-on-surface-variant); }

  .toast-success {
    background-color: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }
  .toast-success .toast-icon { color: var(--color-security-verified); }
  .toast-success .toast-progress { background-color: var(--color-security-verified); }
  .toast-success .toast-dismiss { color: var(--color-on-security-verified-container); }

  .toast-warning {
    background-color: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
  }
  .toast-warning .toast-icon { color: var(--color-security-warning); }
  .toast-warning .toast-progress { background-color: var(--color-security-warning); }
  .toast-warning .toast-dismiss { color: var(--color-on-security-warning-container); }

  .toast-error {
    background-color: var(--color-security-danger-container);
    color: var(--color-on-security-danger-container);
  }
  .toast-error .toast-icon { color: var(--color-security-danger); }
  .toast-error .toast-progress { background-color: var(--color-security-danger); }
  .toast-error .toast-dismiss { color: var(--color-on-security-danger-container); }

  @keyframes slide-in-up {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }
</style>
