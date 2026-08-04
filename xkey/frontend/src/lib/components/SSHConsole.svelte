<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import '@xterm/xterm/css/xterm.css';
  import { SSHConsoleClient, type HostKeyPrompt } from '@go-xkms/sdk';

  /** The WebSocket URL to connect to, e.g. ws://127.0.0.1:PORT/console?token=XXX. */
  export let url: string;
  /** Optional title shown in the status footer. */
  export let title: string = '';
  /** Called once when the session ends (socket closed) — drives tab state. */
  export let onEnded: () => void = () => {};
  /** Placeholder text shown when there is no url (e.g. a restored tab). */
  export let placeholder: string = '';

  let termDiv: HTMLDivElement;
  let status = '';
  let closed = false;
  let client: SSHConsoleClient | null = null;
  let observer: ResizeObserver | null = null;

  /** Host-key prompt awaiting a response (mode "confirm" only); null when none pending. */
  let hostKeyPrompt: HostKeyPrompt | null = null;
  let hostKeyRespond: ((accept: boolean) => void) | null = null;

  /** Guard: no real WS when the Wails backend is absent or url is empty. */
  const isGuarded = typeof window === 'undefined' || !(window as any).go || !url;

  onMount(() => {
    if (isGuarded) return;

    client = new SSHConsoleClient();

    client.onError = (msg: string) => {
      status = msg;
    };

    client.onClose = () => {
      closed = true;
      status = 'Session ended.';
      onEnded();
    };

    client.onHostKey = (prompt, respond) => {
      if (prompt.mode === 'notify') {
        // The server already decided under its accept-new policy; respond()
        // is a no-op here — this is informational only.
        status = `New host key auto-accepted: ${prompt.fingerprint}`;
        return;
      }
      hostKeyPrompt = prompt;
      hostKeyRespond = respond;
    };

    client.open(termDiv, { url });

    observer = new ResizeObserver(() => {
      client?.fit();
    });
    observer.observe(termDiv);
  });

  onDestroy(() => {
    observer?.disconnect();
    client?.dispose();
  });

  /** Responds to a pending "confirm" host-key prompt exactly once, then clears local state. */
  function respondToHostKey(accept: boolean): void {
    const respond = hostKeyRespond;
    hostKeyPrompt = null;
    hostKeyRespond = null;
    respond?.(accept);
  }

  function handleWindowKeydown(e: KeyboardEvent): void {
    if (hostKeyPrompt && e.key === 'Escape') {
      respondToHostKey(false);
    }
  }
</script>

<svelte:window on:keydown={handleWindowKeydown} />

<div class="ssh-console" data-testid="ssh-console">
  {#if isGuarded}
    <div class="ssh-console-placeholder">
      <span class="placeholder-icon">&#9654;</span>
      <span class="placeholder-text">
        {url ? 'SSH console preview (no backend)' : placeholder || 'No console URL provided'}
      </span>
    </div>
  {:else}
    <div class="term-container" bind:this={termDiv}></div>
  {/if}

  {#if status}
    <div class="ssh-console-status" role="status" aria-live="polite">
      {status}
      {#if closed}
        <span class="closed-hint">(closed)</span>
      {/if}
    </div>
  {/if}

  {#if hostKeyPrompt}
    <div
      class="hostkey-overlay"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="ssh-hostkey-title"
      data-testid="ssh-hostkey-prompt"
    >
      <div class="hostkey-dialog">
        <h3 id="ssh-hostkey-title" class="hostkey-title">
          {hostKeyPrompt.known ? 'Host key changed — possible tampering' : 'Unrecognized host key'}
        </h3>
        <div class="hostkey-rows">
          <div class="hostkey-row">
            <span class="hostkey-label">Host</span>
            <span class="hostkey-value">{hostKeyPrompt.host}</span>
          </div>
          <div class="hostkey-row">
            <span class="hostkey-label">Type</span>
            <span class="hostkey-value">{hostKeyPrompt.key_type}</span>
          </div>
          <div class="hostkey-row">
            <span class="hostkey-label">Fingerprint</span>
            <span class="hostkey-value hostkey-fingerprint" data-testid="ssh-hostkey-fingerprint">
              {hostKeyPrompt.fingerprint}
            </span>
          </div>
        </div>
        <div class="hostkey-actions">
          <button
            class="hostkey-btn hostkey-btn-outline"
            data-testid="ssh-hostkey-reject"
            on:click={() => respondToHostKey(false)}
          >
            Reject
          </button>
          <button
            class="hostkey-btn hostkey-btn-primary"
            data-testid="ssh-hostkey-accept"
            on:click={() => respondToHostKey(true)}
          >
            Accept
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .ssh-console {
    position: relative;
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    background-color: #1e1e1e;
    border-radius: var(--radius-md, 8px);
    overflow: hidden;
  }

  .term-container {
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }

  .ssh-console-placeholder {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 12px;
    color: rgba(255, 255, 255, 0.4);
    font-family: var(--font-mono, monospace);
    font-size: 14px;
  }

  .placeholder-icon {
    font-size: 32px;
    opacity: 0.3;
  }

  .placeholder-text {
    font-size: 13px;
  }

  .ssh-console-status {
    flex-shrink: 0;
    padding: 4px 12px;
    background-color: rgba(0, 0, 0, 0.5);
    color: rgba(255, 200, 100, 0.9);
    font-family: var(--font-mono, monospace);
    font-size: 12px;
    border-top: 1px solid rgba(255, 255, 255, 0.08);
  }

  .closed-hint {
    margin-left: 6px;
    color: rgba(255, 100, 100, 0.8);
  }

  /* ── Host-key confirmation overlay ── */
  .hostkey-overlay {
    position: absolute;
    inset: 0;
    z-index: 10;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: rgba(0, 0, 0, 0.75);
  }

  .hostkey-dialog {
    width: 380px;
    max-width: 90%;
    background-color: #252526;
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: var(--radius-md, 8px);
    padding: 20px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
  }

  .hostkey-title {
    margin: 0 0 14px;
    font-family: var(--font-sans, sans-serif);
    font-size: 15px;
    font-weight: 600;
    color: #fff;
  }

  .hostkey-rows {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 20px;
  }

  .hostkey-row {
    display: flex;
    gap: 8px;
    align-items: baseline;
  }

  .hostkey-label {
    flex-shrink: 0;
    width: 84px;
    font-family: var(--font-sans, sans-serif);
    font-size: 12px;
    color: rgba(255, 255, 255, 0.6);
  }

  .hostkey-value {
    font-family: var(--font-mono, monospace);
    font-size: 12px;
    color: rgba(255, 255, 255, 0.92);
    word-break: break-all;
  }

  .hostkey-fingerprint {
    font-size: 12px;
  }

  .hostkey-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  .hostkey-btn {
    font-family: var(--font-sans, sans-serif);
    font-size: 13px;
    font-weight: 500;
    padding: 6px 16px;
    border-radius: var(--radius-full, 999px);
    cursor: pointer;
    border: 1px solid transparent;
  }

  .hostkey-btn-outline {
    background: transparent;
    border-color: rgba(255, 255, 255, 0.3);
    color: rgba(255, 255, 255, 0.92);
  }

  .hostkey-btn-outline:hover {
    background-color: rgba(255, 255, 255, 0.08);
  }

  .hostkey-btn-primary {
    background-color: #0078d4;
    color: #fff;
  }

  .hostkey-btn-primary:hover {
    background-color: #106ebe;
  }
</style>
