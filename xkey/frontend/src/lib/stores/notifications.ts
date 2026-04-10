import { writable, derived } from 'svelte/store';

export type NotificationType = 'info' | 'success' | 'warning' | 'error';

export interface Notification {
  id: string;
  type: NotificationType;
  message: string;
  timestamp: number;
  dismissAfterMs: number;
  progress: number;
}

interface NotificationsState {
  items: Notification[];
}

const DEFAULT_DISMISS_MS = 5000;
const MAX_NOTIFICATIONS = 5;

let nextId = 0;
const timers = new Map<string, ReturnType<typeof setInterval>>();

function generateId(): string {
  nextId += 1;
  return `notif-${nextId}-${Date.now()}`;
}

export const notificationsState = writable<NotificationsState>({ items: [] });

export const notifications = derived(notificationsState, ($s) => $s.items);
export const notificationCount = derived(notificationsState, ($s) => $s.items.length);

function startDismissTimer(id: string, durationMs: number): void {
  const startTime = Date.now();
  const interval = setInterval(() => {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / durationMs, 1);

    if (progress >= 1) {
      removeNotification(id);
      return;
    }

    notificationsState.update((s) => ({
      items: s.items.map((n) =>
        n.id === id ? { ...n, progress } : n
      ),
    }));
  }, 50);

  timers.set(id, interval);
}

export function addNotification(
  type: NotificationType,
  message: string,
  dismissAfterMs: number = DEFAULT_DISMISS_MS
): string {
  const id = generateId();
  const notification: Notification = {
    id,
    type,
    message,
    timestamp: Date.now(),
    dismissAfterMs,
    progress: 0,
  };

  notificationsState.update((s) => {
    let items = [...s.items, notification];
    if (items.length > MAX_NOTIFICATIONS) {
      const removed = items.shift();
      if (removed) {
        const timer = timers.get(removed.id);
        if (timer) {
          clearInterval(timer);
          timers.delete(removed.id);
        }
      }
    }
    return { items };
  });

  if (dismissAfterMs > 0) {
    startDismissTimer(id, dismissAfterMs);
  }

  return id;
}

export function removeNotification(id: string): void {
  const timer = timers.get(id);
  if (timer) {
    clearInterval(timer);
    timers.delete(id);
  }

  notificationsState.update((s) => ({
    items: s.items.filter((n) => n.id !== id),
  }));
}

export function clearAllNotifications(): void {
  for (const [id, timer] of timers) {
    clearInterval(timer);
    timers.delete(id);
  }
  notificationsState.set({ items: [] });
}
