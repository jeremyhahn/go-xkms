import { writable, get } from 'svelte/store';
import { isWailsAvailable, SSHConnectService, SSHConsoleService } from '$lib/api/backend';

/** The console mode used when no per-profile override is set. */
export type ConsoleMode = 'system' | 'embedded' | '';

const STORAGE_KEY = 'xkey:ssh:console_mode';
const HOSTKEY_STORAGE_KEY = 'xkey:ssh:hostkey_checking';
const KNOWN_HOSTS_STORAGE_KEY = 'xkey:ssh:known_hosts_policy';

function persistedStore<T extends string>(key: string, fallback: T) {
  const initial = (localStorage.getItem(key) as T) ?? fallback;
  const { subscribe, set, update } = writable<T>(initial);

  return {
    subscribe,
    set(value: T) {
      localStorage.setItem(key, value);
      set(value);
    },
    update,
  };
}

/** Global default SSH console mode, persisted in localStorage. */
export const sshDefaultConsoleMode = persistedStore<ConsoleMode>(STORAGE_KEY, 'system');

/** Host-key checking policy ('ask' | 'yes' | 'accept-new'), persisted. */
export const sshHostKeyChecking = persistedStore<string>(HOSTKEY_STORAGE_KEY, 'ask');

/** Known-hosts store policy ('barrier' | 'system' | 'both'), persisted. */
export const sshKnownHostsPolicy = persistedStore<string>(KNOWN_HOSTS_STORAGE_KEY, 'barrier');

/**
 * Pushes the persisted SSH policies to the backend services. Called at app
 * startup (and after Settings changes) so the backend defaults never drift
 * from what the Settings page displays — the embedded console and the
 * system-terminal path always share the user's chosen policies.
 */
export async function applySSHPolicies(): Promise<void> {
  if (!isWailsAvailable()) return;
  const checking = get(sshHostKeyChecking);
  const knownHosts = get(sshKnownHostsPolicy);
  await Promise.all([
    SSHConnectService.setStrictHostKeyChecking(checking),
    SSHConsoleService.setHostKeyPolicy(checking),
    SSHConnectService.setKnownHostsPolicy(knownHosts),
    SSHConsoleService.setKnownHostsPolicy(knownHosts),
  ]);
}
