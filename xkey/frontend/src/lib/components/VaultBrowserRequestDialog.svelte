<script lang="ts">
  // Asks the user to approve a web console's request to unlock the password
  // vault with a key factor held by xKey (PIV card, certificate, TPM key).
  // The request arrives from the browser extension; xKey has already checked
  // that the page is the console of the server it is connected to. On
  // approval xKey unlocks the vault itself -- nothing secret goes to the page.
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import { callBackendWithError } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let requestId: string = '';
  export let origin: string = '';
  export let factors: string[] = [];
  export let onClose: () => void = () => {};

  let busy = false;

  async function answer(approve: boolean): Promise<void> {
    busy = true;
    const method = approve ? 'ApproveBrowserVaultRequest' : 'DenyBrowserVaultRequest';
    const { error } = await callBackendWithError<void>('StaticPasswordService', method, requestId);
    busy = false;
    if (error) {
      addNotification('error', error);
    }
    open = false;
    onClose();
  }
</script>

<Modal bind:open title="Unlock your password vault?" maxWidth="440px">
  <div class="vault-request">
    <p>A browser page asks xKey to unlock your password vault:</p>
    <p class="origin" data-testid="vault-request-origin">{origin}</p>
    <p>with {factors.join(', ') || 'a key factor'}.</p>
    <p class="hint">Approve only if you just asked the console to unlock. xKey unlocks the vault itself; the page receives no key.</p>
    <div class="actions">
      <Button variant="secondary" on:click={() => answer(false)} disabled={busy}>Deny</Button>
      <Button variant="primary" on:click={() => answer(true)} disabled={busy}>Approve</Button>
    </div>
  </div>
</Modal>

<style>
  .vault-request { display: flex; flex-direction: column; gap: 0.5rem; }
  .origin { font-family: monospace; font-weight: 600; word-break: break-all; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 0.5rem; }
</style>
