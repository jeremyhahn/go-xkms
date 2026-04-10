<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import Icon from './Icon.svelte';
  import { mdiBluetoothConnect, mdiCellphone, mdiCheck } from '$lib/utils/icons';
  import { isWailsAvailable, callBackendWithError } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onPair: ((deviceAddress: string) => void) | null = null;

  type PairingStep = 'scanning' | 'found' | 'pairing' | 'success' | 'error';

  let step: PairingStep = 'scanning';
  let errorMessage = '';

  interface FoundDevice {
    name: string;
    address: string;
    signal: number;
  }

  let foundDevices: FoundDevice[] = [];
  let selectedDevice: FoundDevice | null = null;

  $: if (open) {
    step = 'scanning';
    errorMessage = '';
    foundDevices = [];
    selectedDevice = null;
    startScan();
  }

  async function startScan(): Promise<void> {
    if (!isWailsAvailable()) {
      errorMessage = 'Backend not available';
      step = 'error';
      return;
    }

    step = 'scanning';
    const { result, error } = await callBackendWithError<Array<{ name: string; address: string; rssi: number }>>(
      'PhoneService',
      'Scan',
      15, // 15 second scan timeout
    );

    if (!open) return; // Dialog was closed during scan

    if (error) {
      errorMessage = error;
      step = 'error';
      return;
    }

    if (!result || result.length === 0) {
      errorMessage = 'No xKey devices found. Make sure the xKey app is running on your phone with BLE advertising enabled.';
      step = 'error';
      return;
    }

    foundDevices = result.map((d) => ({
      name: d.name,
      address: d.address,
      signal: d.rssi,
    }));
    step = 'found';
  }

  async function selectAndPair(device: FoundDevice): Promise<void> {
    selectedDevice = device;
    step = 'pairing';

    if (!isWailsAvailable()) {
      errorMessage = 'Backend not available';
      step = 'error';
      return;
    }

    const { result, error } = await callBackendWithError<{ name: string; address: string }>(
      'PhoneService',
      'Pair',
      device.address,
    );

    if (!open) return; // Dialog was closed during pairing

    if (error) {
      errorMessage = error;
      step = 'error';
      return;
    }

    if (!result) {
      errorMessage = 'Pairing failed - no response from device';
      step = 'error';
      return;
    }

    // Update display name from phone's reported name
    if (result.name) {
      selectedDevice = { ...selectedDevice, name: result.name };
    }

    step = 'success';
    onPair?.(device.address);
  }

  function handleClose(): void {
    open = false;
    onClose();
  }
</script>

<Modal bind:open title="Pair BLE Device" maxWidth="440px">
  <div class="pairing-content">
    {#if step === 'scanning'}
      <div class="pairing-center">
        <LoadingSpinner size={48} />
        <p class="text-body-large pairing-message">Scanning for xKey devices...</p>
        <p class="text-body-small pairing-hint">
          Make sure the xKey app is open on your phone with BLE advertising enabled.
        </p>
      </div>
    {:else if step === 'found'}
      <p class="text-body-medium found-label">Found {foundDevices.length} device(s)</p>
      <div class="device-list">
        {#each foundDevices as device}
          <button class="found-device" on:click={() => selectAndPair(device)}>
            <Icon path={mdiCellphone} size={24} />
            <div class="found-device-info">
              <span class="text-title-small">{device.name}</span>
              <span class="text-body-small found-device-addr">{device.address}</span>
            </div>
            <span class="found-device-signal text-label-small">
              {device.signal > -50 ? 'Strong' : device.signal > -65 ? 'Good' : 'Fair'}
            </span>
          </button>
        {/each}
      </div>
    {:else if step === 'pairing'}
      <div class="pairing-center">
        <div class="pairing-icon">
          <Icon path={mdiBluetoothConnect} size={48} />
        </div>
        <LoadingSpinner size={32} />
        <p class="text-body-large pairing-message">Pairing with {selectedDevice?.name}...</p>
        <p class="text-body-small pairing-hint">Performing secure key exchange via Noise protocol. Check your phone for a confirmation prompt.</p>
      </div>
    {:else if step === 'success'}
      <div class="pairing-center">
        <div class="success-icon">
          <Icon path={mdiCheck} size={48} color="var(--color-security-verified)" />
        </div>
        <p class="text-body-large pairing-message">Successfully paired!</p>
        <p class="text-body-medium">{selectedDevice?.name} is now available as a key backend.</p>
      </div>
    {:else if step === 'error'}
      <div class="pairing-center">
        <p class="text-body-large pairing-error">{errorMessage}</p>
        <Button variant="text" on:click={startScan}>Retry Scan</Button>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    {#if step === 'success'}
      <Button variant="primary" on:click={handleClose}>Done</Button>
    {:else}
      <Button variant="text" on:click={handleClose}>Cancel</Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .pairing-content {
    min-height: 200px;
    display: flex;
    flex-direction: column;
  }

  .pairing-center {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    text-align: center;
    padding: 24px 0;
    flex: 1;
  }

  .pairing-message {
    color: var(--color-on-surface);
    margin: 0;
  }

  .pairing-hint {
    color: var(--color-on-surface-variant);
    margin: 0;
    max-width: 300px;
  }

  .pairing-icon {
    color: var(--color-primary);
    animation: pulse-indicator 2s ease-in-out infinite;
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

  .found-label {
    color: var(--color-on-surface-variant);
    margin: 0 0 12px;
  }

  .device-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .found-device {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background: var(--color-surface-container-lowest);
    cursor: pointer;
    transition: border-color var(--transition-fast),
                background-color var(--transition-fast);
    font-family: var(--font-sans);
    color: var(--color-on-surface);
    text-align: left;
    width: 100%;
  }

  .found-device:hover {
    border-color: var(--color-primary);
    background-color: var(--color-surface-container);
  }

  .found-device-info {
    flex: 1;
    display: flex;
    flex-direction: column;
  }

  .found-device-addr {
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
  }

  .found-device-signal {
    padding: 2px 8px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
  }

  .pairing-error {
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
