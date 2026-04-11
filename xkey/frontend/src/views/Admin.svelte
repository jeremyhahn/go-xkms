<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import {
    mdiKey, mdiChip, mdiShieldCheckOutline, mdiCellphone,
    mdiCloudOutline, mdiAtom, mdiAccountGroup,
    mdiLanConnect, mdiLanDisconnect, mdiPlus, mdiDelete, mdiRefresh,
    mdiMagnify, mdiCog, mdiCheckCircle, mdiAlertCircle,
    mdiChevronUp, mdiChevronDown
  } from '$lib/utils/icons';
  import { navigateTo } from '$lib/stores/app';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';
  import type {
    BackendBackendInfo,
    PKCS11ProbeResult, PKCS11ModuleInfo, PKCS11TokenInfo, PKCS11ConnectionInfo
  } from '$lib/api/backend';

  // Backend type definitions for the "Add Backend" flow
  interface AvailableBackendType {
    type: string;
    name: string;
    description: string;
    icon: string;
    requiresConfig: boolean;
    supportsConnectionTest?: boolean;
    configFields?: ConfigField[];
  }

  interface ConfigField {
    key: string;
    label: string;
    type: 'text' | 'password' | 'number' | 'select' | 'file';
    placeholder?: string;
    required?: boolean;
    options?: { value: string; label: string }[];
  }

  // Full backend types that support sealing/unsealing (not key providers)
  // These implement the complete backend interface
  // Configuration is at the service/account level - keys are enumerated after connection
  const allBackendTypes: AvailableBackendType[] = [
    {
      type: 'yubikey',
      name: 'YubiKey',
      description: 'YubiKey PIV via PKCS#11 (auto-detected)',
      icon: mdiShieldCheckOutline,
      requiresConfig: true,
      supportsConnectionTest: true,
      configFields: [],
    },
    {
      type: 'pkcs11',
      name: 'PKCS#11 / HSM',
      description: 'Hardware Security Module via PKCS#11',
      icon: mdiShieldCheckOutline,
      requiresConfig: true,
      supportsConnectionTest: true,
      // PKCS#11 has custom fields handled separately (initialize checkbox, PIN fields)
      configFields: [
        { key: 'library_path', label: 'Library Path', type: 'file', placeholder: '/usr/lib/softhsm/libsofthsm2.so', required: true },
      ],
    },
    {
      type: 'awskms',
      name: 'AWS KMS',
      description: 'Amazon Web Services Key Management Service',
      icon: mdiCloudOutline,
      requiresConfig: true,
      supportsConnectionTest: true,
      configFields: [
        { key: 'region', label: 'Region', type: 'text', placeholder: 'us-east-1', required: true },
        { key: 'access_key_id', label: 'Access Key ID', type: 'text', placeholder: 'Leave empty to use IAM role or environment' },
        { key: 'secret_access_key', label: 'Secret Access Key', type: 'password', placeholder: 'Leave empty to use IAM role or environment' },
        { key: 'session_token', label: 'Session Token', type: 'password', placeholder: 'Optional, for temporary credentials' },
        { key: 'profile', label: 'AWS Profile', type: 'text', placeholder: 'default' },
      ],
    },
    {
      type: 'gcpkms',
      name: 'GCP Cloud KMS',
      description: 'Google Cloud Platform Key Management Service',
      icon: mdiCloudOutline,
      requiresConfig: true,
      supportsConnectionTest: true,
      configFields: [
        { key: 'project', label: 'Project ID', type: 'text', required: true, placeholder: 'my-gcp-project' },
        { key: 'location', label: 'Location', type: 'text', placeholder: 'global', required: true },
        { key: 'keyring', label: 'Key Ring', type: 'text', required: true, placeholder: 'my-keyring' },
        { key: 'credentials_file', label: 'Credentials JSON File', type: 'file', placeholder: 'Leave empty to use application default credentials' },
      ],
    },
    {
      type: 'azurekv',
      name: 'Azure Key Vault',
      description: 'Microsoft Azure Key Vault',
      icon: mdiCloudOutline,
      requiresConfig: true,
      supportsConnectionTest: true,
      configFields: [
        { key: 'vault_url', label: 'Vault URL', type: 'text', placeholder: 'https://myvault.vault.azure.net', required: true },
        { key: 'tenant_id', label: 'Tenant ID', type: 'text', placeholder: 'Leave empty to use environment or managed identity' },
        { key: 'client_id', label: 'Client ID', type: 'text', placeholder: 'Leave empty to use environment or managed identity' },
        { key: 'client_secret', label: 'Client Secret', type: 'password', placeholder: 'Leave empty to use environment or managed identity' },
      ],
    },
    {
      type: 'vault',
      name: 'HashiCorp Vault',
      description: 'HashiCorp Vault Transit Secrets Engine',
      icon: mdiCloudOutline,
      requiresConfig: true,
      supportsConnectionTest: true,
      configFields: [
        { key: 'address', label: 'Vault Address', type: 'text', placeholder: 'http://127.0.0.1:8200', required: true },
        { key: 'token', label: 'Token', type: 'password', placeholder: 'Leave empty to use VAULT_TOKEN environment variable' },
        { key: 'mount_path', label: 'Transit Mount Path', type: 'text', placeholder: 'transit' },
        { key: 'namespace', label: 'Namespace', type: 'text', placeholder: 'Optional, for Vault Enterprise' },
      ],
    },
  ];

  // Backend types that are compiled into the binary (fetched from backend)
  let compiledBackendTypes: Set<string> = new Set();
  let backendTypesLoaded: boolean = false;

  // Computed: filter out backends that are not compiled in or already installed
  $: availableBackendTypes = allBackendTypes.filter(bt => {
    // Only show backends that are compiled in
    // YubiKey depends on PKCS#11 being compiled in
    if (bt.type === 'yubikey') {
      if (!compiledBackendTypes.has('yubikey') && !compiledBackendTypes.has('pkcs11')) return false;
      // Hide if a YubiKey backend is already installed
      return !backends.some(b => b.id.includes('ykcs11'));
    }
    if (!compiledBackendTypes.has(bt.type)) return false;
    // PKCS#11 can have multiple modules, so always show it
    if (bt.type === 'pkcs11') return true;
    // For other types, hide if already installed
    return !backends.some(b => b.type === bt.type);
  });

  // Configured backends from the server/registry
  let backends: {
    id: string;
    name: string;
    type: string;
    status: 'connected' | 'disconnected';
    keyCount: number;
    icon: string;
    deviceName?: string;
    description?: string;
  }[] = [];

  // UI State
  let loading = true;
  let showAddBackendDialog = false;
  let selectedBackendType: AvailableBackendType | null = null;
  let backendConfig: Record<string, string> = {};
  let addingBackend = false;

  // PKCS#11 specific state (for probing)
  let pkcs11ProbeResults: PKCS11ProbeResult[] = [];
  let pkcs11Probing = false;

  // PKCS#11 initialization and PIN state
  let pkcs11Initialize = false;
  let pkcs11TokenLabel = '';
  let pkcs11SoPin = '';
  let pkcs11SoPinConfirm = '';
  let pkcs11UserPin = '';
  let pkcs11UserPinConfirm = '';
  let pkcs11SlotId = 0;
  let pkcs11ShowAdvanced = false;
  let pkcs11AvailableSlots: { slotId: number; label: string; initialized: boolean }[] = [];
  let pkcs11ProbingSlots = false;

  // YubiKey specific state
  let yukDetecting = false;
  let yukLibraryPath = '';
  let yukDetected = false;
  let yukDetectError = '';
  let yukUserPin = '';
  let yukMgmtKey = '010203040506070801020304050607080102030405060708';
  let yukSlotId = 0;
  let yukAvailableSlots: { slotId: number; label: string; initialized: boolean }[] = [];
  let yukProbingSlots = false;

  // Connection test state
  let connectionTestStatus: 'idle' | 'testing' | 'success' | 'error' = 'idle';
  let connectionTestMessage = '';

  // Connect backend dialog state
  let showConnectDialog = false;
  let connectBackendId = '';
  let connectBackendType = '';
  let connectBackendName = '';
  let connectUserPin = '';
  let connectMgmtKey = '';
  let connectSlotId = 0;
  let connecting = false;

  // Configure backend dialog state
  let showConfigureDialog = false;
  let configureBackendId = '';
  let configureBackendType = '';
  let configureBackendName = '';
  let configureBackendStatus = '';
  let configureBackendKeyCount = 0;
  let configureBackendCapabilities: BackendCapabilityInfo | null = null;
  let configureBackendMetadata: Record<string, string> = {};
  let configurePKCS11Slots: PKCS11SlotInfo[] = [];
  let configureLoading = false;

  // PKCS11SlotInfo from backend.ts (hardware details)
  interface PKCS11SlotInfo {
    slot_id: number;
    label: string;
    serial: string;
    manufacturer: string;
    model: string;
    token_present: boolean;
    initialized: boolean;
    hardware_version: string;
    firmware_version: string;
  }

  interface BackendCapabilityInfo {
    signing: boolean;
    encryption: boolean;
    decryption: boolean;
    key_encapsulation: boolean;
    sealing: boolean;
    attestation: boolean;
    hardware_backed: boolean;
    quantum_signing: boolean;
  }

  // Icon mapping
  const iconMap: Record<string, string> = {
    software: mdiKey,
    pkcs8: mdiKey,
    symmetric: mdiKey,
    tpm2: mdiChip,
    pkcs11: mdiShieldCheckOutline,
    smartcardhsm: mdiShieldCheckOutline,
    yubikey: mdiShieldCheckOutline,
    phone: mdiCellphone,
    awskms: mdiCloudOutline,
    gcpkms: mdiCloudOutline,
    azurekv: mdiCloudOutline,
    vault: mdiCloudOutline,
    threshold: mdiAccountGroup,
    frost: mdiAccountGroup,
    quantum: mdiAtom,
  };

  async function loadBackends(): Promise<void> {
    loading = true;
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }

    const backendList = await callBackend<BackendBackendInfo[]>('AdminService', 'ListBackends');
    if (backendList) {
      backends = backendList.map(b => ({
        id: b.id,
        name: b.display_name || b.id,
        type: b.type,
        status: b.connected ? 'connected' : 'disconnected',
        keyCount: b.key_count,
        icon: iconMap[b.type] || mdiKey,
        deviceName: b.device_name,
        description: b.description,
      }));
    }
    loading = false;
  }

  interface AvailableBackendTypeInfo {
    type: string;
    name: string;
    description: string;
    available: boolean;
  }

  async function loadAvailableBackendTypes(): Promise<void> {
    console.log('loadAvailableBackendTypes: starting, isWailsAvailable=', isWailsAvailable());
    if (!isWailsAvailable()) {
      console.log('loadAvailableBackendTypes: Wails not available, returning');
      return;
    }

    try {
      const types = await callBackend<AvailableBackendTypeInfo[]>('AdminService', 'GetAvailableBackendTypes');
      console.log('GetAvailableBackendTypes returned:', JSON.stringify(types, null, 2));
      if (types) {
        const availableTypes = types.filter(t => t.available);
        console.log('Available backend types (filtered by available=true):', JSON.stringify(availableTypes, null, 2));
        compiledBackendTypes = new Set(availableTypes.map(t => t.type));
        console.log('compiledBackendTypes set:', [...compiledBackendTypes]);
        backendTypesLoaded = true;
      } else {
        console.log('GetAvailableBackendTypes returned null/undefined');
      }
    } catch (err) {
      console.error('loadAvailableBackendTypes error:', err);
    }
  }

  function openAddBackendDialog(): void {
    selectedBackendType = null;
    backendConfig = {};
    showAddBackendDialog = true;
  }

  function selectBackendType(backendType: AvailableBackendType): void {
    selectedBackendType = backendType;
    backendConfig = {};
    connectionTestStatus = 'idle';
    connectionTestMessage = '';
    // Reset PKCS#11 specific state
    pkcs11Initialize = false;
    pkcs11TokenLabel = '';
    pkcs11SoPin = '';
    pkcs11SoPinConfirm = '';
    pkcs11UserPin = '';
    pkcs11UserPinConfirm = '';
    pkcs11SlotId = 0;
    pkcs11ShowAdvanced = false;
    pkcs11ProbeResults = [];
    pkcs11AvailableSlots = [];
    pkcs11ProbingSlots = false;
    // Reset YubiKey specific state
    yukDetecting = false;
    yukLibraryPath = '';
    yukDetected = false;
    yukDetectError = '';
    yukUserPin = '';
    yukMgmtKey = '010203040506070801020304050607080102030405060708';
    yukSlotId = 0;
    yukAvailableSlots = [];
    yukProbingSlots = false;
    // Pre-fill defaults
    if (backendType.configFields) {
      for (const field of backendType.configFields) {
        backendConfig[field.key] = '';
      }
    }
    // Auto-detect YubiKey library
    if (backendType.type === 'yubikey') {
      detectYubiKey();
    }
  }

  function cancelBackendTypeSelection(): void {
    selectedBackendType = null;
    backendConfig = {};
    connectionTestStatus = 'idle';
    connectionTestMessage = '';
    // Reset PKCS#11 specific state
    pkcs11Initialize = false;
    pkcs11TokenLabel = '';
    pkcs11SoPin = '';
    pkcs11SoPinConfirm = '';
    pkcs11UserPin = '';
    pkcs11UserPinConfirm = '';
    pkcs11SlotId = 0;
    pkcs11ShowAdvanced = false;
    pkcs11ProbeResults = [];
    pkcs11AvailableSlots = [];
    pkcs11ProbingSlots = false;
    // Reset YubiKey state
    yukDetecting = false;
    yukLibraryPath = '';
    yukDetected = false;
    yukDetectError = '';
    yukUserPin = '';
    yukMgmtKey = '010203040506070801020304050607080102030405060708';
    yukSlotId = 0;
    yukAvailableSlots = [];
    yukProbingSlots = false;
  }

  // Detect YubiKey PKCS#11 library and probe slots
  async function detectYubiKey(): Promise<void> {
    yukDetecting = true;
    yukDetectError = '';
    try {
      const result = await callBackend('PKCS11Service', 'DetectYubiKey') as { found: boolean; library_path: string; error: string };
      if (result?.found) {
        yukDetected = true;
        yukLibraryPath = result.library_path;
        // Auto-probe slots
        yukProbingSlots = true;
        try {
          const slots = await callBackend('PKCS11Service', 'ProbeSlots', yukLibraryPath) as any[];
          if (slots && slots.length > 0) {
            yukAvailableSlots = slots.map((s: any) => ({
              slotId: s.slot_id ?? 0,
              label: s.label ?? '',
              initialized: s.initialized ?? false,
            }));
            // Auto-select first initialized slot
            const initSlot = yukAvailableSlots.find(s => s.initialized);
            if (initSlot) yukSlotId = initSlot.slotId;
          }
        } catch {
          // Slot probing failed - user can still enter manually
        } finally {
          yukProbingSlots = false;
        }
      } else {
        yukDetected = false;
        yukDetectError = result?.error || 'libykcs11.so not found on this system. Install the YubiKey PKCS#11 module.';
      }
    } catch (err) {
      yukDetected = false;
      yukDetectError = 'Failed to detect YubiKey library';
    } finally {
      yukDetecting = false;
    }
  }

  // Probe PKCS#11 module slots when library path changes
  async function probePKCS11Slots(libraryPath: string): Promise<void> {
    if (!libraryPath || !libraryPath.trim()) {
      pkcs11AvailableSlots = [];
      return;
    }

    pkcs11ProbingSlots = true;
    try {
      const slots = await callBackend<{ slot_id: number; label: string; initialized: boolean }[]>(
        'PKCS11Service', 'ProbeSlots', libraryPath
      );
      if (slots && slots.length > 0) {
        pkcs11AvailableSlots = slots.map(s => ({
          slotId: s.slot_id,
          label: s.label || `Slot ${s.slot_id}`,
          initialized: s.initialized
        }));
        // Auto-select first available slot
        if (pkcs11AvailableSlots.length > 0) {
          pkcs11SlotId = pkcs11AvailableSlots[0].slotId;
        }
      } else {
        pkcs11AvailableSlots = [];
      }
    } catch (err) {
      console.error('Failed to probe PKCS#11 slots:', err);
      pkcs11AvailableSlots = [];
    } finally {
      pkcs11ProbingSlots = false;
    }
  }

  async function handleTestConnection(): Promise<void> {
    if (!selectedBackendType) return;

    // Validate required fields first
    if (selectedBackendType.configFields) {
      for (const field of selectedBackendType.configFields) {
        if (field.required && !backendConfig[field.key]?.trim()) {
          addNotification('error', `${field.label} is required`);
          return;
        }
      }
    }

    // PKCS#11 specific validation
    if (selectedBackendType.type === 'pkcs11') {
      if (!pkcs11UserPin) {
        addNotification('error', 'User PIN is required to test connection');
        return;
      }
      if (pkcs11Initialize) {
        // Can't test connection when initializing - need to initialize first
        addNotification('info', 'Cannot test connection when initializing. The token will be initialized when you click Add Backend.');
        return;
      }
    }

    // YubiKey specific validation
    if (selectedBackendType.type === 'yubikey') {
      if (!yukUserPin) {
        addNotification('error', 'User PIN is required to test connection');
        return;
      }
      if (!yukLibraryPath) {
        addNotification('error', 'YubiKey library not detected');
        return;
      }
    }

    connectionTestStatus = 'testing';
    connectionTestMessage = 'Testing connection...';

    try {
      // Build config with PKCS#11 specific fields
      const testConfig: Record<string, string> = { ...backendConfig };
      if (selectedBackendType.type === 'pkcs11') {
        testConfig['user_pin'] = pkcs11UserPin;
        testConfig['slot_id'] = String(pkcs11SlotId);
      } else if (selectedBackendType.type === 'yubikey') {
        testConfig['library_path'] = yukLibraryPath;
        testConfig['user_pin'] = yukUserPin;
        testConfig['slot_id'] = String(yukSlotId);
      }

      const result = await callBackend<{ success: boolean; message: string }>(
        'AdminService', 'TestBackendConnection',
        selectedBackendType.type, testConfig
      );

      if (result?.success) {
        connectionTestStatus = 'success';
        connectionTestMessage = result.message || 'Connection successful';
        addNotification('success', connectionTestMessage);
      } else {
        connectionTestStatus = 'error';
        connectionTestMessage = result?.message || 'Connection failed';
        addNotification('error', connectionTestMessage);
      }
    } catch (err) {
      connectionTestStatus = 'error';
      connectionTestMessage = err instanceof Error ? err.message : 'Connection test failed';
      addNotification('error', connectionTestMessage);
    }
  }

  async function handleProbePKCS11(): Promise<void> {
    pkcs11Probing = true;
    const results = await callBackend<PKCS11ProbeResult[]>('PKCS11Service', 'ProbeModules');
    pkcs11ProbeResults = results ?? [];
    pkcs11Probing = false;
    if (pkcs11ProbeResults.length === 0) {
      addNotification('info', 'No PKCS#11 modules found on this system');
    } else {
      addNotification('success', `Found ${pkcs11ProbeResults.length} PKCS#11 module(s)`);
    }
  }

  function selectProbeResult(result: PKCS11ProbeResult): void {
    backendConfig['library_path'] = result.library_path;
    backendConfig['display_name'] = result.display_name;
    // Probe slots for the selected module
    probePKCS11Slots(result.library_path);
  }

  // Handle manual library path changes
  function handleLibraryPathChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    const value = input.value;
    backendConfig['library_path'] = value;
    // Probe slots when path changes (with debounce)
    if (value && value.endsWith('.so')) {
      probePKCS11Slots(value);
    }
  }

  async function handleAddBackend(): Promise<void> {
    if (!selectedBackendType) return;

    // Validate required fields
    if (selectedBackendType.configFields) {
      for (const field of selectedBackendType.configFields) {
        if (field.required && !backendConfig[field.key]?.trim()) {
          addNotification('error', `${field.label} is required`);
          return;
        }
      }
    }

    addingBackend = true;

    try {
      // Handle based on backend type
      switch (selectedBackendType.type) {
        case 'yubikey': {
          // Validate YubiKey fields
          if (!yukDetected || !yukLibraryPath) {
            addNotification('error', 'YubiKey library not detected. Install the ykcs11 package.');
            addingBackend = false;
            return;
          }
          if (!yukUserPin) {
            addNotification('error', 'User PIN is required');
            addingBackend = false;
            return;
          }

          // Register the YubiKey as a PKCS#11 module
          const yukDisplayName = 'YubiKey PIV';
          const yukModuleId = await callBackend<string>(
            'PKCS11Service', 'RegisterModule',
            yukLibraryPath,
            yukDisplayName
          );

          if (!yukModuleId) {
            addNotification('error', 'Failed to register YubiKey module');
            break;
          }

          // Connect with management key as SO PIN
          const yukConnectOk = await callBackendVoid(
            'PKCS11Service', 'Connect',
            yukModuleId, yukSlotId, yukUserPin, yukMgmtKey
          );

          if (yukConnectOk) {
            addNotification('success', `YubiKey connected successfully`);
          } else {
            addNotification('warning', 'YubiKey registered but connection failed. Check your PIN.');
          }
          break;
        }
        case 'pkcs11': {
          // Validate PKCS#11 specific fields
          if (!pkcs11UserPin) {
            addNotification('error', 'User PIN is required');
            addingBackend = false;
            return;
          }

          if (pkcs11Initialize) {
            // Validate initialization fields
            if (!pkcs11TokenLabel) {
              addNotification('error', 'Token Label is required for initialization');
              addingBackend = false;
              return;
            }
            if (!pkcs11SoPin) {
              addNotification('error', 'SO PIN is required for initialization');
              addingBackend = false;
              return;
            }
            if (pkcs11SoPin !== pkcs11SoPinConfirm) {
              addNotification('error', 'SO PIN confirmation does not match');
              addingBackend = false;
              return;
            }
            if (pkcs11UserPin !== pkcs11UserPinConfirm) {
              addNotification('error', 'User PIN confirmation does not match');
              addingBackend = false;
              return;
            }
          }

          // Register PKCS#11 module — prefer user-entered custom name,
          // then probed display name, then library basename as fallback.
          const libPath = backendConfig['library_path'];
          const customName = backendConfig['custom_name']?.trim();
          const probedName = backendConfig['display_name'];
          const displayName = customName || probedName
              || libPath.split('/').pop()?.replace(/\.so.*$/, '') || libPath;
          const moduleId = await callBackend<string>(
            'PKCS11Service', 'RegisterModule',
            libPath,
            displayName
          );

          if (!moduleId) {
            addNotification('error', 'Failed to register PKCS#11 module');
            break;
          }

          if (pkcs11Initialize) {
            // Initialize the token on the specified slot
            const initOk = await callBackendVoid(
              'PKCS11Service', 'InitializeToken',
              moduleId, pkcs11SlotId, pkcs11TokenLabel, pkcs11SoPin, pkcs11UserPin
            );
            if (!initOk) {
              addNotification('error', `Failed to initialize token on slot ${pkcs11SlotId}`);
              break;
            }
            addNotification('success', `Token initialized successfully on slot ${pkcs11SlotId}`);
          }

          // Connect to the token on the specified slot
          const connectOk = await callBackendVoid(
            'PKCS11Service', 'Connect',
            moduleId, pkcs11SlotId, pkcs11UserPin, pkcs11SoPin
          );

          if (connectOk) {
            addNotification('success', `PKCS#11 backend connected: ${pkcs11TokenLabel || displayName}`);
          } else {
            addNotification('warning', 'Module registered but connection failed. Check your PIN.');
          }
          break;
        }
        case 'awskms':
        case 'gcpkms':
        case 'azurekv':
        case 'vault': {
          // Configure cloud/remote backend
          const ok = await callBackendVoid('AdminService', 'ConfigureBackend', selectedBackendType.type, backendConfig);
          if (ok) {
            addNotification('success', `${selectedBackendType.name} backend configured. Go to Store → Keys to view keys.`);
          } else {
            addNotification('error', `Failed to configure ${selectedBackendType.name} backend`);
          }
          break;
        }
      }
    } finally {
      addingBackend = false;
      showAddBackendDialog = false;
      selectedBackendType = null;
      backendConfig = {};
      await loadBackends();
    }
  }

  async function handleRemoveBackend(backendId: string, backendType: string): Promise<void> {
    if (backendType === 'pkcs11') {
      const ok = await callBackendVoid('PKCS11Service', 'UnregisterModule', backendId);
      if (ok) {
        addNotification('success', 'Backend removed');
        await loadBackends();
      } else {
        addNotification('error', 'Failed to remove backend');
      }
    } else {
      // TODO: Call AdminService.RemoveBackend(id)
      addNotification('info', 'Backend removal not implemented for this type');
    }
  }

  // Check if a backend ID belongs to a YubiKey (uses libykcs11).
  function isYubiKeyBackend(backendId: string): boolean {
    return backendId.includes('ykcs11');
  }

  async function handleConnectBackend(backendId: string, backendType: string): Promise<void> {
    if (backendType === 'pkcs11') {
      // Find the backend to get its display name
      const backend = backends.find(b => b.id === backendId);
      connectBackendId = backendId;
      connectBackendType = backendType;
      connectBackendName = backend?.deviceName || backend?.name || backendId;
      connectUserPin = '';
      connectMgmtKey = '';
      connectSlotId = 0; // Default slot, could be enhanced to remember/lookup
      connecting = false;
      showConnectDialog = true;
    } else {
      addNotification('info', `Connect to ${backendId} - not implemented for ${backendType}`);
    }
  }

  async function handleConnectConfirm(): Promise<void> {
    if (!connectUserPin) {
      addNotification('error', 'User PIN is required');
      return;
    }

    connecting = true;
    try {
      if (connectBackendType === 'pkcs11') {
        const ok = await callBackendVoid(
          'PKCS11Service', 'Connect',
          connectBackendId, connectSlotId, connectUserPin, connectMgmtKey
        );
        if (ok) {
          addNotification('success', `Connected to ${connectBackendName}`);
          showConnectDialog = false;
          await loadBackends();
        } else {
          addNotification('error', 'Failed to connect. Check your PIN.');
        }
      }
    } catch (err) {
      addNotification('error', err instanceof Error ? err.message : 'Connection failed');
    } finally {
      connecting = false;
    }
  }

  function cancelConnect(): void {
    showConnectDialog = false;
    connectBackendId = '';
    connectBackendType = '';
    connectBackendName = '';
    connectUserPin = '';
    connectMgmtKey = '';
    connectSlotId = 0;
    connecting = false;
  }

  async function handleDisconnectBackend(backendId: string, backendType: string): Promise<void> {
    if (backendType === 'pkcs11') {
      // Parse module and slot from backend ID
      const ok = await callBackendVoid('PKCS11Service', 'Disconnect', backendId, 0);
      if (ok) {
        addNotification('success', 'Disconnected from backend');
        await loadBackends();
      }
    } else {
      addNotification('info', 'Disconnect not implemented for this type');
    }
  }

  async function handleConfigureBackend(backendId: string, backendType: string): Promise<void> {
    configureBackendId = backendId;
    configureBackendType = backendType;
    configureLoading = true;
    showConfigureDialog = true;
    configurePKCS11Slots = [];
    configureBackendCapabilities = null;
    configureBackendMetadata = {};

    try {
      // Get backend info from the list we already have
      const backend = backends.find(b => b.id === backendId);
      if (backend) {
        configureBackendName = backend.deviceName || backend.name || backendId;
        configureBackendStatus = backend.status;
        configureBackendKeyCount = backend.keyCount;
      }

      // Get detailed backend info from the service
      const info = await callBackend<BackendBackendInfo>('AdminService', 'GetBackendInfo', backendId);
      if (info) {
        configureBackendName = info.display_name || info.device_name || info.id;
        configureBackendKeyCount = info.key_count;
        configureBackendCapabilities = info.capabilities ?? null;
        configureBackendMetadata = info.metadata ?? {};
      }

      // For PKCS#11 backends, get slot details with hardware info
      if (backendType === 'pkcs11') {
        // Try to get module slots for hardware details
        const module = await callBackend<PKCS11ModuleInfo>('PKCS11Service', 'GetModule', backendId);
        if (module?.slots) {
          configurePKCS11Slots = module.slots.map(s => ({
            slot_id: s.slot_id,
            label: s.label,
            serial: s.serial,
            manufacturer: s.manufacturer,
            model: s.model,
            token_present: s.token_present,
            initialized: s.initialized,
            hardware_version: s.hardware_version,
            firmware_version: s.firmware_version,
          }));
        }
      }
    } catch (err) {
      console.error('Failed to load backend details:', err);
      addNotification('error', 'Failed to load backend details');
    } finally {
      configureLoading = false;
    }
  }

  function closeConfigureDialog(): void {
    showConfigureDialog = false;
    configureBackendId = '';
    configureBackendType = '';
    configureBackendName = '';
    configureBackendStatus = '';
    configureBackendKeyCount = 0;
    configureBackendCapabilities = null;
    configureBackendMetadata = {};
    configurePKCS11Slots = [];
    configureLoading = false;
  }

  onMount(async () => {
    await Promise.all([
      loadBackends(),
      loadAvailableBackendTypes(),
    ]);
  });
</script>

<div class="admin-view">
  <GradientHeader title="Backend Administration" subtitle="Configure cryptographic backends" />

  <div class="admin-content">
    <!-- Configured Backends -->
    <section>
      <div class="section-header">
        <h2 class="text-title-medium section-heading">Configured Backends</h2>
        <div class="section-actions">
          <Button variant="outline" icon={mdiRefresh} on:click={loadBackends} disabled={loading}>
            Refresh
          </Button>
          <Button variant="primary" icon={mdiPlus} on:click={openAddBackendDialog}>
            Add Backend
          </Button>
        </div>
      </div>

      {#if loading}
        <div class="loading-state">
          <span class="text-body-medium">Loading backends...</span>
        </div>
      {:else if backends.length === 0}
        <Card variant="outlined">
          <div class="empty-state">
            <Icon path={mdiKey} size={48} color="var(--color-on-surface-variant)" />
            <h3 class="text-title-medium">No Backends Configured</h3>
            <p class="text-body-medium">Click "Add Backend" to configure a cryptographic backend.</p>
          </div>
        </Card>
      {:else}
        <div class="backends-grid">
          {#each backends as backend}
            <Card variant="elevated">
              <div class="backend-card">
                <div class="backend-header">
                  <div class="backend-icon" class:backend-active={backend.status === 'connected'}>
                    <Icon path={backend.icon} size={24} />
                  </div>
                  <StatusBadge status={backend.status} />
                </div>
                <h3 class="text-title-medium backend-name">{backend.deviceName || backend.name}</h3>
                <span class="text-body-small backend-type">{backend.type}{backend.deviceName ? ` (${backend.name})` : ''}</span>
                {#if backend.description}
                  <span class="text-body-small backend-description">{backend.description}</span>
                {/if}
                <div class="backend-stat">
                  <span class="text-display-small backend-count">{backend.keyCount}</span>
                  <span class="text-label-small backend-count-label">keys</span>
                </div>
                <div class="backend-actions">
                  {#if backend.status === 'connected'}
                    <Button variant="text" size="sm" icon={mdiLanDisconnect} on:click={() => handleDisconnectBackend(backend.id, backend.type)}>
                      Disconnect
                    </Button>
                  {:else}
                    <Button variant="text" size="sm" icon={mdiLanConnect} on:click={() => handleConnectBackend(backend.id, backend.type)}>
                      Connect
                    </Button>
                  {/if}
                  <Button variant="text" size="sm" icon={mdiCog} on:click={() => handleConfigureBackend(backend.id, backend.type)}>
                    Configure
                  </Button>
                  <Button variant="text" size="sm" icon={mdiDelete} on:click={() => handleRemoveBackend(backend.id, backend.type)}>
                    Remove
                  </Button>
                </div>
              </div>
            </Card>
          {/each}
        </div>
      {/if}
    </section>
  </div>
</div>

<!-- Add Backend Dialog -->
<Modal bind:open={showAddBackendDialog} title={selectedBackendType ? `Configure ${selectedBackendType.name}` : 'Add Backend'} maxWidth="600px">
  {#if !selectedBackendType}
    <!-- Backend Type Selection -->
    {#if !backendTypesLoaded}
      <div class="empty-state" data-testid="add-backend-unavailable">
        <Icon path={mdiKey} size={48} color="var(--color-on-surface-variant)" />
        <h3 class="text-title-medium">Backend Types Unavailable</h3>
        <p class="text-body-medium">The backend service is not available. Please ensure xKey is running.</p>
      </div>
    {:else if availableBackendTypes.length === 0}
      <div class="empty-state" data-testid="add-backend-all-configured">
        <Icon path={mdiKey} size={48} color="var(--color-on-surface-variant)" />
        <h3 class="text-title-medium">All Backends Configured</h3>
        <p class="text-body-medium">All available backend types are already configured. You can add additional PKCS#11 modules if needed.</p>
      </div>
    {:else}
      <div class="backend-type-grid">
        {#each availableBackendTypes as backendType}
          <button class="backend-type-card" on:click={() => selectBackendType(backendType)}>
            <div class="backend-type-icon">
              <Icon path={backendType.icon} size={32} />
            </div>
            <div class="backend-type-info">
              <span class="text-title-small">{backendType.name}</span>
              <span class="text-body-small">{backendType.description}</span>
            </div>
          </button>
        {/each}
      </div>
    {/if}
  {:else}
    <!-- Backend Configuration Form -->
    <div class="dialog-content">
        <!-- PKCS#11 has special probe functionality and PIN fields -->
        {#if selectedBackendType.type === 'yubikey'}
          <!-- YubiKey auto-detection and configuration -->
          <div class="yubikey-section">
            {#if yukDetecting}
              <div class="detection-status">
                <span class="text-body-medium">Detecting YubiKey PKCS#11 library...</span>
              </div>
            {:else if yukDetected}
              <div class="detection-status detection-success">
                <span class="text-body-medium">YubiKey library found: <code>{yukLibraryPath}</code></span>
              </div>

              {#if yukProbingSlots}
                <div class="form-field">
                  <span class="text-body-small">Probing YubiKey slots...</span>
                </div>
              {:else if yukAvailableSlots.length > 0}
                <div class="form-field">
                  <label class="text-label-medium" for="yuk-slot-select">Token Slot</label>
                  <select id="yuk-slot-select" class="text-input" bind:value={yukSlotId}>
                    {#each yukAvailableSlots as slot}
                      <option value={slot.slotId}>
                        Slot {slot.slotId}: {slot.label || 'Unknown'} {slot.initialized ? '' : '(uninitialized)'}
                      </option>
                    {/each}
                  </select>
                </div>
              {:else}
                <div class="form-field">
                  <label class="text-label-medium" for="yuk-slot-id">Slot ID</label>
                  <input id="yuk-slot-id" type="number" class="text-input" min="0" placeholder="0" bind:value={yukSlotId} />
                  <span class="field-hint text-body-small">Usually 0 for YubiKey PIV.</span>
                </div>
              {/if}

              <div class="form-field">
                <label class="text-label-medium" for="yuk-user-pin">
                  User PIN <span class="required">*</span>
                </label>
                <input
                  id="yuk-user-pin"
                  type="password"
                  class="text-input"
                  placeholder="Enter YubiKey PIV PIN"
                  bind:value={yukUserPin}
                />
                <span class="field-hint text-body-small">Your YubiKey PIV PIN (default: 123456)</span>
              </div>

              <div class="form-field">
                <label class="text-label-medium" for="yuk-mgmt-key">
                  Management Key
                </label>
                <input
                  id="yuk-mgmt-key"
                  type="password"
                  class="text-input"
                  placeholder="Enter management key (hex)"
                  bind:value={yukMgmtKey}
                />
                <span class="field-hint text-body-small">Required for key generation (SO login). Pre-filled with YubiKey factory default.</span>
              </div>
            {:else}
              <div class="detection-status detection-error">
                <span class="text-body-medium">{yukDetectError}</span>
                <Button variant="outline" on:click={detectYubiKey} size="small">Retry Detection</Button>
              </div>
            {/if}
          </div>

        {:else if selectedBackendType.type === 'pkcs11'}
          <div class="probe-section">
            <Button variant="outline" icon={mdiMagnify} on:click={handleProbePKCS11} disabled={pkcs11Probing}>
              {pkcs11Probing ? 'Probing...' : 'Probe System for Modules'}
            </Button>
            {#if pkcs11ProbeResults.length > 0}
              <div class="probe-results">
                <span class="text-label-medium">Detected Modules:</span>
                {#each pkcs11ProbeResults as result}
                  <button class="probe-result" on:click={() => selectProbeResult(result)}>
                    <span class="text-body-medium">{result.display_name}</span>
                    <span class="text-body-small font-mono">{result.library_path}</span>
                  </button>
                {/each}
              </div>
            {/if}
          </div>

          <!-- Custom Display Name -->
          <div class="form-field">
            <label class="text-label-medium" for="pkcs11-custom-name">
              Display Name
            </label>
            <input
              id="pkcs11-custom-name"
              data-testid="pkcs11-custom-name"
              type="text"
              class="text-input"
              placeholder={backendConfig['display_name'] || 'Auto-detected name'}
              bind:value={backendConfig['custom_name']}
            />
            <span class="field-hint text-body-small">Optional friendly name shown in the backend filter. Defaults to detected token name.</span>
          </div>

          <!-- Initialize Token Checkbox -->
          <div class="form-field checkbox-field">
            <label class="checkbox-label">
              <input type="checkbox" bind:checked={pkcs11Initialize} />
              <span class="text-label-medium">Initialize token</span>
            </label>
            <span class="field-hint text-body-small">
              Check this to initialize a new or uninitialized token. This will erase any existing data on the token.
            </span>
          </div>

          {#if pkcs11Initialize}
            <!-- Token Label (only when initializing) -->
            <div class="form-field">
              <label class="text-label-medium" for="pkcs11-token-label">
                Token Label <span class="required">*</span>
              </label>
              <input
                id="pkcs11-token-label"
                type="text"
                class="text-input"
                placeholder="MyToken"
                bind:value={pkcs11TokenLabel}
              />
              <span class="field-hint text-body-small">A name for this token (max 32 characters)</span>
            </div>

            <!-- SO PIN fields (only when initializing) -->
            <div class="form-field">
              <label class="text-label-medium" for="pkcs11-so-pin">
                Security Officer (SO) PIN <span class="required">*</span>
              </label>
              <input
                id="pkcs11-so-pin"
                type="password"
                class="text-input"
                placeholder="Enter SO PIN"
                bind:value={pkcs11SoPin}
              />
            </div>
            <div class="form-field">
              <label class="text-label-medium" for="pkcs11-so-pin-confirm">
                Confirm SO PIN <span class="required">*</span>
              </label>
              <input
                id="pkcs11-so-pin-confirm"
                type="password"
                class="text-input"
                placeholder="Confirm SO PIN"
                bind:value={pkcs11SoPinConfirm}
              />
              {#if pkcs11SoPin && pkcs11SoPinConfirm && pkcs11SoPin !== pkcs11SoPinConfirm}
                <span class="field-error text-body-small">PINs do not match</span>
              {/if}
            </div>

            <!-- User PIN fields (when initializing) -->
            <div class="form-field">
              <label class="text-label-medium" for="pkcs11-user-pin">
                User PIN <span class="required">*</span>
              </label>
              <input
                id="pkcs11-user-pin"
                type="password"
                class="text-input"
                placeholder="Enter User PIN"
                bind:value={pkcs11UserPin}
              />
            </div>
            <div class="form-field">
              <label class="text-label-medium" for="pkcs11-user-pin-confirm">
                Confirm User PIN <span class="required">*</span>
              </label>
              <input
                id="pkcs11-user-pin-confirm"
                type="password"
                class="text-input"
                placeholder="Confirm User PIN"
                bind:value={pkcs11UserPinConfirm}
              />
              {#if pkcs11UserPin && pkcs11UserPinConfirm && pkcs11UserPin !== pkcs11UserPinConfirm}
                <span class="field-error text-body-small">PINs do not match</span>
              {/if}
            </div>
          {:else}
            <!-- User PIN only (connecting to existing token) -->
            <div class="form-field">
              <label class="text-label-medium" for="pkcs11-user-pin">
                User PIN <span class="required">*</span>
              </label>
              <input
                id="pkcs11-user-pin"
                type="password"
                class="text-input"
                placeholder="Enter User PIN to connect"
                bind:value={pkcs11UserPin}
              />
              <span class="field-hint text-body-small">Enter the User PIN to connect to an existing initialized token</span>
            </div>
          {/if}

          <!-- Slot Selection -->
          {#if pkcs11ProbingSlots}
            <div class="form-field">
              <span class="text-body-small">Probing slots...</span>
            </div>
          {:else if pkcs11AvailableSlots.length > 0}
            <div class="form-field">
              <label class="text-label-medium" for="pkcs11-slot-select">
                Token Slot
              </label>
              <select
                id="pkcs11-slot-select"
                class="text-input"
                bind:value={pkcs11SlotId}
              >
                {#each pkcs11AvailableSlots as slot}
                  <option value={slot.slotId}>
                    {slot.label} (Slot {slot.slotId}) {slot.initialized ? '✓' : '- uninitialized'}
                  </option>
                {/each}
              </select>
              <span class="field-hint text-body-small">
                Select the token slot to use
              </span>
            </div>
          {/if}

          <!-- Advanced Settings (collapsed by default) -->
          <div class="advanced-section">
            <button
              type="button"
              class="advanced-toggle"
              on:click={() => pkcs11ShowAdvanced = !pkcs11ShowAdvanced}
            >
              <Icon path={pkcs11ShowAdvanced ? mdiChevronUp : mdiChevronDown} size={20} />
              <span>Advanced Settings</span>
            </button>

            {#if pkcs11ShowAdvanced}
              <div class="advanced-content">
                <div class="form-field">
                  <label class="text-label-medium" for="pkcs11-slot-id">
                    Slot ID (manual)
                  </label>
                  <input
                    id="pkcs11-slot-id"
                    type="number"
                    class="text-input"
                    min="0"
                    placeholder="0"
                    bind:value={pkcs11SlotId}
                  />
                  <span class="field-hint text-body-small">
                    Override slot ID manually if the dropdown doesn't show correct slots.
                  </span>
                </div>
              </div>
            {/if}
          </div>
        {/if}

        <!-- Dynamic config fields -->
        {#if selectedBackendType.configFields}
          {#each selectedBackendType.configFields as field}
            <div class="form-field">
              <label class="text-label-medium" for="config-{field.key}">
                {field.label}
                {#if field.required}<span class="required">*</span>{/if}
              </label>
              {#if field.type === 'password'}
                <input
                  id="config-{field.key}"
                  type="password"
                  class="text-input"
                  placeholder={field.placeholder || ''}
                  bind:value={backendConfig[field.key]}
                />
              {:else if field.type === 'number'}
                <input
                  id="config-{field.key}"
                  type="number"
                  class="text-input"
                  placeholder={field.placeholder || ''}
                  bind:value={backendConfig[field.key]}
                />
              {:else if field.type === 'select' && field.options}
                <select id="config-{field.key}" class="text-input" bind:value={backendConfig[field.key]}>
                  <option value="">Select...</option>
                  {#each field.options as opt}
                    <option value={opt.value}>{opt.label}</option>
                  {/each}
                </select>
              {:else if field.key === 'library_path' && selectedBackendType?.type === 'pkcs11'}
                <input
                  id="config-{field.key}"
                  type="text"
                  class="text-input"
                  placeholder={field.placeholder || ''}
                  bind:value={backendConfig[field.key]}
                  on:blur={handleLibraryPathChange}
                />
              {:else}
                <input
                  id="config-{field.key}"
                  type="text"
                  class="text-input"
                  placeholder={field.placeholder || ''}
                  bind:value={backendConfig[field.key]}
                />
              {/if}
            </div>
          {/each}
        {/if}

        <!-- Connection Test Section -->
        {#if selectedBackendType.supportsConnectionTest}
          <div class="connection-test-section">
            <div class="connection-test-row">
              <Button
                variant="outline"
                icon={mdiLanConnect}
                on:click={handleTestConnection}
                disabled={connectionTestStatus === 'testing'}
              >
                {connectionTestStatus === 'testing' ? 'Testing...' : 'Test Connection'}
              </Button>
              {#if connectionTestStatus === 'success'}
                <div class="connection-status connection-success">
                  <Icon path={mdiCheckCircle} size={20} />
                  <span class="text-body-small">{connectionTestMessage}</span>
                </div>
              {:else if connectionTestStatus === 'error'}
                <div class="connection-status connection-error">
                  <Icon path={mdiAlertCircle} size={20} />
                  <span class="text-body-small">{connectionTestMessage}</span>
                </div>
              {/if}
            </div>
            <p class="text-body-small connection-hint">
              Test the connection before adding the backend to verify your configuration.
            </p>
          </div>
        {/if}
    </div>
  {/if}
  <svelte:fragment slot="actions">
    {#if selectedBackendType}
      <Button variant="text" on:click={cancelBackendTypeSelection}>Back</Button>
    {/if}
    <Button variant="text" on:click={() => showAddBackendDialog = false}>Cancel</Button>
    {#if selectedBackendType}
      <Button variant="primary" on:click={handleAddBackend} disabled={addingBackend}>
        {addingBackend ? 'Adding...' : 'Add Backend'}
      </Button>
    {/if}
  </svelte:fragment>
</Modal>

<!-- Connect Backend Dialog (for reconnecting disconnected backends) -->
<Modal bind:open={showConnectDialog} title={`Connect to ${connectBackendName}`} maxWidth="400px">
  <div class="dialog-content">
    <p class="text-body-medium connect-description">
      Enter your User PIN to reconnect to this backend.
    </p>

    <div class="form-field">
      <label class="text-label-medium" for="connect-user-pin">
        User PIN <span class="required">*</span>
      </label>
      <input
        id="connect-user-pin"
        type="password"
        class="text-input"
        placeholder="Enter User PIN"
        bind:value={connectUserPin}
        on:keydown={(e) => e.key === 'Enter' && handleConnectConfirm()}
      />
    </div>

    {#if connectBackendType === 'pkcs11'}
      <div class="form-field">
        <label class="text-label-medium" for="connect-slot-id">
          Slot ID
        </label>
        <input
          id="connect-slot-id"
          type="number"
          class="text-input"
          min="0"
          placeholder="0"
          bind:value={connectSlotId}
        />
        <span class="field-hint text-body-small">
          Usually 0 for single-token devices. Check your token documentation if unsure.
        </span>
      </div>

      {#if isYubiKeyBackend(connectBackendId)}
        <div class="form-field">
          <label class="text-label-medium" for="connect-mgmt-key">
            Management Key
          </label>
          <input
            id="connect-mgmt-key"
            type="password"
            class="text-input"
            placeholder="Enter management key (hex)"
            bind:value={connectMgmtKey}
          />
          <span class="field-hint text-body-small">
            Required for FIDO2 key generation on YubiKey PIV.
          </span>
        </div>
      {/if}
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={cancelConnect} disabled={connecting}>Cancel</Button>
    <Button variant="primary" icon={mdiLanConnect} on:click={handleConnectConfirm} disabled={connecting || !connectUserPin}>
      {connecting ? 'Connecting...' : 'Connect'}
    </Button>
  </svelte:fragment>
</Modal>

<!-- Configure Backend Dialog -->
<Modal bind:open={showConfigureDialog} title={`Configure ${configureBackendName}`} maxWidth="600px">
  <div class="dialog-content">
    {#if configureLoading}
      <div class="loading-state">
        <p class="text-body-medium">Loading backend details...</p>
      </div>
    {:else}
      <!-- Backend Status Overview -->
      <div class="config-section">
        <h4 class="text-label-large">Status</h4>
        <div class="config-grid">
          <div class="config-item">
            <span class="config-label">ID</span>
            <span class="config-value font-mono">{configureBackendId}</span>
          </div>
          <div class="config-item">
            <span class="config-label">Type</span>
            <span class="config-value">{configureBackendType}</span>
          </div>
          <div class="config-item">
            <span class="config-label">Status</span>
            <StatusBadge status={configureBackendStatus === 'connected' ? 'connected' : 'disconnected'} />
          </div>
          <div class="config-item">
            <span class="config-label">Keys Stored</span>
            <span class="config-value">{configureBackendKeyCount}</span>
          </div>
        </div>
      </div>

      <!-- PKCS#11 Hardware Details -->
      {#if configureBackendType === 'pkcs11' && configurePKCS11Slots.length > 0}
        <div class="config-section">
          <h4 class="text-label-large">Hardware Information</h4>
          {#each configurePKCS11Slots as slot}
            <div class="config-grid hardware-grid">
              <div class="config-item">
                <span class="config-label">Slot ID</span>
                <span class="config-value">{slot.slot_id}</span>
              </div>
              <div class="config-item">
                <span class="config-label">Token Label</span>
                <span class="config-value">{slot.label || 'Not set'}</span>
              </div>
              <div class="config-item">
                <span class="config-label">Manufacturer</span>
                <span class="config-value">{slot.manufacturer || 'Unknown'}</span>
              </div>
              <div class="config-item">
                <span class="config-label">Model</span>
                <span class="config-value">{slot.model || 'Unknown'}</span>
              </div>
              <div class="config-item">
                <span class="config-label">Serial</span>
                <span class="config-value font-mono">{slot.serial || 'N/A'}</span>
              </div>
              <div class="config-item">
                <span class="config-label">Hardware Version</span>
                <span class="config-value">{slot.hardware_version || 'N/A'}</span>
              </div>
              <div class="config-item">
                <span class="config-label">Firmware Version</span>
                <span class="config-value">{slot.firmware_version || 'N/A'}</span>
              </div>
              <div class="config-item">
                <span class="config-label">Initialized</span>
                <span class="config-value">{slot.initialized ? 'Yes' : 'No'}</span>
              </div>
            </div>
          {/each}
        </div>
      {/if}

      <!-- Capabilities -->
      {#if configureBackendCapabilities}
        <div class="config-section">
          <h4 class="text-label-large">Capabilities</h4>
          <div class="capability-badges">
            {#if configureBackendCapabilities.signing}
              <span class="capability-badge">Signing</span>
            {/if}
            {#if configureBackendCapabilities.encryption}
              <span class="capability-badge">Encryption</span>
            {/if}
            {#if configureBackendCapabilities.decryption}
              <span class="capability-badge">Decryption</span>
            {/if}
            {#if configureBackendCapabilities.sealing}
              <span class="capability-badge">Sealing</span>
            {/if}
            {#if configureBackendCapabilities.attestation}
              <span class="capability-badge">Attestation</span>
            {/if}
            {#if configureBackendCapabilities.hardware_backed}
              <span class="capability-badge hardware">Hardware Backed</span>
            {/if}
            {#if configureBackendCapabilities.key_encapsulation}
              <span class="capability-badge">Key Encapsulation</span>
            {/if}
            {#if configureBackendCapabilities.quantum_signing}
              <span class="capability-badge quantum">Post-Quantum</span>
            {/if}
          </div>
        </div>
      {/if}

      <!-- Backend Metadata -->
      {#if Object.keys(configureBackendMetadata).length > 0}
        <div class="config-section">
          <h4 class="text-label-large">Additional Information</h4>
          <div class="config-grid">
            {#each Object.entries(configureBackendMetadata) as [key, value]}
              <div class="config-item">
                <span class="config-label">{key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                <span class="config-value font-mono">{value}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="primary" on:click={closeConfigureDialog}>Close</Button>
  </svelte:fragment>
</Modal>

<style>
  .admin-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .admin-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
  }

  .section-heading {
    margin: 0;
    color: var(--color-on-surface);
  }

  .section-actions {
    display: flex;
    gap: 8px;
  }

  .loading-state {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 48px;
    color: var(--color-on-surface-variant);
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 48px;
    text-align: center;
    gap: 12px;
  }

  .empty-state h3 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .empty-state p {
    margin: 0;
    color: var(--color-on-surface-variant);
    max-width: 400px;
  }

  .backends-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px;
  }

  .backend-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .backend-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .backend-icon {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .backend-icon.backend-active {
    background: var(--gradient-primary);
    color: #FFFFFF;
  }

  .backend-name {
    margin: 0;
    color: var(--color-on-surface);
  }

  .backend-type {
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
  }

  .backend-description {
    color: var(--color-on-surface-variant);
  }

  .backend-stat {
    display: flex;
    align-items: baseline;
    gap: 4px;
    margin-top: 8px;
  }

  .backend-count {
    color: var(--color-primary);
    font-weight: 600;
  }

  .backend-count-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
  }

  .backend-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }

  /* Add Backend Dialog */
  .backend-type-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
    max-height: 400px;
    overflow-y: auto;
  }

  .backend-type-card {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background: var(--color-surface);
    cursor: pointer;
    transition: all 0.2s ease;
    text-align: left;
  }

  .backend-type-card:hover {
    border-color: var(--color-primary);
    background: var(--color-primary-container);
  }

  .backend-type-icon {
    width: 48px;
    height: 48px;
    border-radius: var(--radius-md);
    background: var(--color-surface-container-high);
    color: var(--color-primary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .backend-type-info {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .backend-type-info .text-title-small {
    color: var(--color-on-surface);
  }

  .backend-type-info .text-body-small {
    color: var(--color-on-surface-variant);
  }

  .dialog-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-width: 320px;
  }

  /* Configure dialog styles */
  .config-section {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .config-section:last-child {
    border-bottom: none;
    padding-bottom: 0;
  }

  .config-section h4 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .config-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px 24px;
  }

  .hardware-grid {
    grid-template-columns: repeat(2, 1fr);
  }

  @media (max-width: 500px) {
    .config-grid {
      grid-template-columns: 1fr;
    }
  }

  .config-item {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .config-label {
    font-size: 12px;
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .config-value {
    font-size: 14px;
    color: var(--color-on-surface);
  }

  .font-mono {
    font-family: 'Roboto Mono', monospace;
  }

  .capability-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .capability-badge {
    padding: 4px 12px;
    border-radius: 16px;
    font-size: 12px;
    font-weight: 500;
    background-color: var(--color-surface-variant);
    color: var(--color-on-surface-variant);
  }

  .capability-badge.hardware {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .capability-badge.quantum {
    background-color: var(--color-tertiary-container);
    color: var(--color-on-tertiary-container);
  }

  .loading-state {
    padding: 24px;
    text-align: center;
    color: var(--color-on-surface-variant);
  }

  .yubikey-section {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .detection-status {
    padding: 12px;
    border-radius: 8px;
    background: var(--color-surface-variant);
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .detection-status code {
    font-size: 0.85em;
    background: var(--color-surface);
    padding: 2px 6px;
    border-radius: 4px;
  }

  .detection-success {
    background: var(--color-primary-container, #d4edda);
  }

  .detection-error {
    background: var(--color-error-container, #f8d7da);
  }

  .probe-section {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .probe-results {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .probe-result {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    cursor: pointer;
    text-align: left;
    transition: all 0.2s ease;
  }

  .probe-result:hover {
    border-color: var(--color-primary);
    background: var(--color-primary-container);
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field label {
    color: var(--color-on-surface-variant);
  }

  .form-field .required {
    color: var(--color-error);
  }

  .field-hint {
    color: var(--color-on-surface-variant);
    opacity: 0.8;
  }

  .field-error {
    color: var(--color-error);
  }

  .checkbox-field {
    padding: 12px 0;
  }

  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
  }

  .checkbox-label input[type="checkbox"] {
    width: 18px;
    height: 18px;
    accent-color: var(--color-primary);
    cursor: pointer;
  }

  /* Advanced Settings Section */
  .advanced-section {
    margin-top: 16px;
    padding-top: 16px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .advanced-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: none;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    color: var(--color-on-surface-variant);
    font-size: 14px;
    cursor: pointer;
    transition: all 0.2s ease;
    width: 100%;
    justify-content: flex-start;
  }

  .advanced-toggle:hover {
    background: var(--color-surface-container-high);
    border-color: var(--color-outline);
  }

  .advanced-content {
    margin-top: 12px;
    padding: 16px;
    background: var(--color-surface-container-low);
    border-radius: var(--radius-sm);
  }

  .text-input {
    padding: 12px 16px;
    border: 1px solid var(--color-outline);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface);
    color: var(--color-on-surface);
    font-size: 14px;
    font-family: inherit;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  .text-input:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 2px var(--color-primary-container);
  }

  .text-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .font-mono {
    font-family: var(--font-mono);
  }

  /* Connection Test Section */
  .connection-test-section {
    margin-top: 8px;
    padding-top: 16px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .connection-test-row {
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }

  .connection-status {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: var(--radius-sm);
  }

  .connection-success {
    background-color: var(--color-success-container, rgba(76, 175, 80, 0.1));
    color: var(--color-success, #4CAF50);
  }

  .connection-error {
    background-color: var(--color-error-container, rgba(244, 67, 54, 0.1));
    color: var(--color-error);
  }

  .connection-hint {
    margin: 8px 0 0;
    color: var(--color-on-surface-variant);
  }

  .connect-description {
    margin: 0 0 8px;
    color: var(--color-on-surface-variant);
  }

  @media (max-width: 600px) {
    .backend-type-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
