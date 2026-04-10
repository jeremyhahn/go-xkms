import { writable } from 'svelte/store';

export interface TouchRequestInfo {
  operation: string;
  rp_id: string;
  rp_name: string;
  user_name: string;
}

export const touchPending = writable(false);
export const touchRequest = writable<TouchRequestInfo | null>(null);

export function setTouchPending(info: TouchRequestInfo): void {
  touchRequest.set(info);
  touchPending.set(true);
}

export function clearTouchPending(): void {
  touchRequest.set(null);
  touchPending.set(false);
}
