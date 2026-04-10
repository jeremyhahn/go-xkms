<script lang="ts">
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';
  import { mdiCellphone, mdiLanConnect } from '$lib/utils/icons';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onChooseBLE: () => void = () => {};
  export let onChooseAgent: () => void = () => {};
</script>

<Modal bind:open title="Pair New Device" maxWidth="440px">
  <div class="chooser-content">
    <p class="text-body-medium chooser-description">
      Choose the type of device to pair.
    </p>

    <div class="chooser-options">
      <button class="chooser-option" on:click={onChooseBLE}>
        <div class="option-icon ble-icon">
          <Icon path={mdiCellphone} size={32} />
        </div>
        <div class="option-info">
          <span class="text-title-small">BLE Device</span>
          <span class="text-body-small option-desc">
            Pair a phone running the xKey app via Bluetooth Low Energy.
          </span>
        </div>
      </button>

      <button class="chooser-option" on:click={onChooseAgent}>
        <div class="option-icon agent-icon">
          <Icon path={mdiLanConnect} size={32} />
        </div>
        <div class="option-info">
          <span class="text-title-small">Remote xKey Agent</span>
          <span class="text-body-small option-desc">
            Connect to a remote machine running <code>xkey serve</code>.
          </span>
        </div>
      </button>
    </div>
  </div>

  <svelte:fragment slot="actions">
    <button class="cancel-btn text-label-large" on:click={onClose}>Cancel</button>
  </svelte:fragment>
</Modal>

<style>
  .chooser-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .chooser-description {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .chooser-options {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .chooser-option {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px;
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

  .chooser-option:hover {
    border-color: var(--color-primary);
    background-color: var(--color-surface-container);
  }

  .option-icon {
    width: 56px;
    height: 56px;
    border-radius: var(--radius-md);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .ble-icon {
    background: var(--gradient-primary);
    color: #fff;
  }

  .agent-icon {
    background: linear-gradient(135deg, var(--color-tertiary), var(--color-tertiary-container));
    color: var(--color-on-tertiary);
  }

  .option-info {
    display: flex;
    flex-direction: column;
    gap: 4px;
    flex: 1;
  }

  .option-desc {
    color: var(--color-on-surface-variant);
    line-height: 1.4;
  }

  .option-desc code {
    background: var(--color-surface-container);
    padding: 1px 4px;
    border-radius: 3px;
    font-family: var(--font-mono);
    font-size: 0.85em;
  }

  .cancel-btn {
    border: none;
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    padding: 8px 16px;
    border-radius: var(--radius-full);
    font-family: var(--font-sans);
    transition: background-color var(--transition-fast);
  }

  .cancel-btn:hover {
    background-color: var(--color-surface-container);
  }
</style>
