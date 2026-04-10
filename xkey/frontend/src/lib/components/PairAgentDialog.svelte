<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import Icon from './Icon.svelte';
  import { mdiLanConnect, mdiCheck } from '$lib/utils/icons';
  import { isWailsAvailable, callBackendWithError } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onPair: ((address: string) => void) | null = null;

  type PairStep = 'input' | 'connecting' | 'success' | 'error';

  let step: PairStep = 'input';
  let hostPort = '';
  let errorMessage = '';

  $: if (open) {
    step = 'input';
    errorMessage = '';
    hostPort = '';
  }

  $: canConnect = hostPort.trim().length > 0;

  async function handleConnect(): Promise<void> {
    if (!canConnect) return;

    step = 'connecting';

    if (!isWailsAvailable()) {
      errorMessage = 'Backend not available';
      step = 'error';
      return;
    }

    const { result, error } = await callBackendWithError<{ address: string }>(
      'AgentService',
      'Pair',
      hostPort.trim(),
    );

    if (!open) return;

    if (error) {
      errorMessage = error;
      step = 'error';
      return;
    }

    step = 'success';
    onPair?.(hostPort.trim());
  }

  function handleClose(): void {
    open = false;
    onClose();
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter' && canConnect && step === 'input') {
      handleConnect();
    }
  }
</script>

<Modal bind:open title="Pair Remote Agent" maxWidth="440px">
  <div class="agent-content">
    {#if step === 'input'}
      <div class="agent-center">
        <div class="agent-icon">
          <Icon path={mdiLanConnect} size={48} />
        </div>
        <p class="text-body-medium agent-description">
          Connect to a remote xKey agent running <code>xkey serve</code>.
          Enter the host and port of the remote agent.
        </p>
        <div class="input-group">
          <label class="text-label-small input-label" for="agent-host">Host:Port</label>
          <input
            id="agent-host"
            class="text-body-medium agent-input"
            type="text"
            placeholder="192.168.1.50:8443"
            bind:value={hostPort}
            on:keydown={handleKeydown}
          />
        </div>
      </div>
    {:else if step === 'connecting'}
      <div class="agent-center">
        <div class="connecting-icon">
          <Icon path={mdiLanConnect} size={48} />
        </div>
        <LoadingSpinner size={32} />
        <p class="text-body-large agent-message">Connecting to {hostPort}...</p>
        <p class="text-body-small agent-hint">Establishing secure connection to the remote agent.</p>
      </div>
    {:else if step === 'success'}
      <div class="agent-center">
        <div class="success-icon">
          <Icon path={mdiCheck} size={48} color="var(--color-security-verified)" />
        </div>
        <p class="text-body-large agent-message">Agent paired!</p>
        <p class="text-body-medium">Connected to remote agent at {hostPort}.</p>
      </div>
    {:else if step === 'error'}
      <div class="agent-center">
        <p class="text-body-large agent-error">{errorMessage}</p>
        <Button variant="text" on:click={() => { step = 'input'; }}>Try Again</Button>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    {#if step === 'input'}
      <Button variant="text" on:click={handleClose}>Cancel</Button>
      <Button variant="primary" on:click={handleConnect} disabled={!canConnect}>Connect</Button>
    {:else if step === 'success'}
      <Button variant="primary" on:click={handleClose}>Done</Button>
    {:else if step === 'error'}
      <Button variant="text" on:click={handleClose}>Close</Button>
    {:else}
      <Button variant="text" on:click={handleClose}>Cancel</Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .agent-content {
    min-height: 200px;
    display: flex;
    flex-direction: column;
  }

  .agent-center {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    text-align: center;
    padding: 24px 0;
    flex: 1;
  }

  .agent-icon {
    color: var(--color-primary);
  }

  .agent-description {
    color: var(--color-on-surface-variant);
    margin: 0;
    max-width: 340px;
    line-height: 1.5;
  }

  .agent-description code {
    background: var(--color-surface-container);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 0.85em;
  }

  .input-group {
    width: 100%;
    max-width: 300px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    text-align: left;
  }

  .input-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .agent-input {
    width: 100%;
    padding: 10px 14px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 0.9rem;
    outline: none;
    transition: border-color var(--transition-fast);
    box-sizing: border-box;
  }

  .agent-input:focus {
    border-color: var(--color-primary);
  }

  .agent-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.5;
  }

  .connecting-icon {
    color: var(--color-primary);
    animation: pulse-indicator 2s ease-in-out infinite;
  }

  .agent-message {
    color: var(--color-on-surface);
    margin: 0;
  }

  .agent-hint {
    color: var(--color-on-surface-variant);
    margin: 0;
    max-width: 300px;
  }

  .success-icon {
    width: 72px;
    height: 72px;
    border-radius: 50%;
    background-color: var(--color-security-verified-container);
    display: flex;
    align-items: center;
    justify-content: center;
    animation: scale-in 300ms cubic-bezier(0.34, 1.56, 0.64, 1);
  }

  .agent-error {
    color: var(--color-error);
    margin: 0;
  }

  @keyframes pulse-indicator {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  @keyframes scale-in {
    from { opacity: 0; transform: scale(0.5); }
    to { opacity: 1; transform: scale(1); }
  }
</style>
