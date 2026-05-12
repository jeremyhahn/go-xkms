import { writable } from 'svelte/store';

export type NotificationType = 'success' | 'error' | 'warning' | 'info';

export interface Notification {
  id: number;
  type: NotificationType;
  message: string;
  duration: number;
}

let nextId = 0;
const DEFAULT_DURATION = 5000;

export const notifications = writable<Notification[]>([]);

/** Add a notification and auto-dismiss after the given duration. */
export function addNotification(
  type: NotificationType,
  message: string,
  duration: number = DEFAULT_DURATION,
): number {
  const id = nextId++;
  const notification: Notification = { id, type, message, duration };

  notifications.update((list) => [...list, notification]);

  if (duration > 0) {
    setTimeout(() => removeNotification(id), duration);
  }

  return id;
}

/** Remove a notification by id. */
export function removeNotification(id: number): void {
  notifications.update((list) => list.filter((n) => n.id !== id));
}

/** Remove all notifications. */
export function clearNotifications(): void {
  notifications.set([]);
}

/** Convenience: success notification. */
export function notifySuccess(message: string, duration?: number): number {
  return addNotification('success', message, duration);
}

/** Convenience: error notification. */
export function notifyError(message: string, duration?: number): number {
  return addNotification('error', message, duration ?? 8000);
}

/** Convenience: warning notification. */
export function notifyWarning(message: string, duration?: number): number {
  return addNotification('warning', message, duration);
}

/** Convenience: info notification. */
export function notifyInfo(message: string, duration?: number): number {
  return addNotification('info', message, duration);
}
