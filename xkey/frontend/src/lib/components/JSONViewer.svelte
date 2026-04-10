<script lang="ts">
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { mdiContentCopy, mdiDownload } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';

  /** The raw JSON string to display. */
  export let json: string = '';

  /** Optional filename for the save dialog (without extension). */
  export let filename: string = 'response';

  /** Maximum height for the scrollable area. Set 0 for unlimited. */
  export let maxHeight: number = 500;

  let formatted = '';

  $: {
    try {
      const parsed = JSON.parse(json);
      formatted = JSON.stringify(parsed, null, 2);
    } catch {
      formatted = json;
    }
  }

  async function copyJSON(): Promise<void> {
    if (isWailsAvailable()) {
      const ok = await callBackendVoid('ClipboardService', 'CopyWithClear', formatted);
      if (!ok) {
        try {
          await navigator.clipboard.writeText(formatted);
        } catch {
          addNotification('error', 'Failed to copy to clipboard');
          return;
        }
      }
    } else {
      try {
        await navigator.clipboard.writeText(formatted);
      } catch {
        addNotification('error', 'Failed to copy to clipboard');
        return;
      }
    }
    addNotification('success', 'JSON copied to clipboard');
  }

  async function saveJSON(): Promise<void> {
    if (isWailsAvailable()) {
      const path = await callBackend<string>('AppService', 'SaveTextFile', `${filename}.json`, formatted);
      if (path) {
        addNotification('success', `Saved to ${path}`);
      }
      // null means user cancelled or error — don't show notification
    } else {
      // Fallback for non-Wails mode
      const blob = new Blob([formatted], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}.json`;
      a.click();
      URL.revokeObjectURL(url);
      addNotification('success', `Saved as ${filename}.json`);
    }
  }
</script>

<div class="json-viewer" data-testid="json-viewer">
  <div class="json-toolbar">
    <Button variant="text" size="sm" icon={mdiContentCopy} on:click={copyJSON}>Copy</Button>
    <Button variant="text" size="sm" icon={mdiDownload} on:click={saveJSON}>Save</Button>
  </div>
  <div class="json-content" style={maxHeight > 0 ? `max-height: ${maxHeight}px` : ''}>
    <pre class="json-pre">{formatted}</pre>
  </div>
</div>

<style>
  .json-viewer {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    overflow: hidden;
  }

  .json-toolbar {
    display: flex;
    gap: 4px;
    padding: 4px 8px;
    background-color: var(--color-surface-container);
    border-bottom: 1px solid var(--color-outline-variant);
    justify-content: flex-end;
  }

  .json-content {
    overflow: auto;
    background-color: var(--color-surface-container-lowest);
  }

  .json-pre {
    margin: 0;
    padding: 12px;
    font-family: var(--font-mono);
    font-size: 13px;
    color: var(--color-on-surface);
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.5;
  }
</style>
