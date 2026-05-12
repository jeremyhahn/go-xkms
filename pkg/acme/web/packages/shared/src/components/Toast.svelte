<script lang="ts">
  import { fly } from 'svelte/transition';
  import { notifications, removeNotification, type NotificationType } from '../stores/notifications';

  const typeStyles: Record<NotificationType, { bg: string; icon: string; border: string }> = {
    success: {
      bg: 'bg-green-50 dark:bg-green-900/20',
      border: 'border-green-400 dark:border-green-600',
      icon: 'M5 13l4 4L19 7',
    },
    error: {
      bg: 'bg-red-50 dark:bg-red-900/20',
      border: 'border-red-400 dark:border-red-600',
      icon: 'M6 18L18 6M6 6l12 12',
    },
    warning: {
      bg: 'bg-amber-50 dark:bg-amber-900/20',
      border: 'border-amber-400 dark:border-amber-600',
      icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z',
    },
    info: {
      bg: 'bg-sky-50 dark:bg-sky-900/20',
      border: 'border-sky-400 dark:border-sky-600',
      icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    },
  };

  const textColors: Record<NotificationType, string> = {
    success: 'text-green-800 dark:text-green-200',
    error: 'text-red-800 dark:text-red-200',
    warning: 'text-amber-800 dark:text-amber-200',
    info: 'text-sky-800 dark:text-sky-200',
  };
</script>

<div class="fixed bottom-4 right-4 z-[100] flex flex-col gap-2" aria-live="polite">
  {#each $notifications as notification (notification.id)}
    <div
      class="flex items-start gap-3 rounded-lg border px-4 py-3 shadow-lg {typeStyles[notification.type].bg} {typeStyles[notification.type].border}"
      transition:fly={{ x: 100, duration: 200 }}
      role="alert"
    >
      <svg
        class="mt-0.5 h-5 w-5 flex-shrink-0 {textColors[notification.type]}"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        stroke-width="2"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          d={typeStyles[notification.type].icon}
        />
      </svg>

      <p class="flex-1 text-sm {textColors[notification.type]}">
        {notification.message}
      </p>

      <button
        class="flex-shrink-0 rounded p-0.5 {textColors[notification.type]} hover:opacity-70"
        on:click={() => removeNotification(notification.id)}
        aria-label="Dismiss"
      >
        <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>
  {/each}
</div>
