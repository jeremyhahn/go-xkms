// API
export { ApiClient, apiClient } from './api/client';
export { isWailsAvailable, getApiBaseUrl, initTransport } from './api/transport';
export type * from './api/types';
export { setupApi } from './api/setup';
export type {
  SetupStatusResponse,
  SetupBarrierRequest,
  SetupBarrierResponse,
  SetupCARequest,
} from './api/setup';

// Stores
export { theme, themeMode, toggleTheme, setThemeMode, initTheme } from './stores/theme';
export type { ThemeMode, ResolvedTheme } from './stores/theme';
export {
  notifications,
  addNotification,
  removeNotification,
  clearNotifications,
  notifySuccess,
  notifyError,
  notifyWarning,
  notifyInfo,
} from './stores/notifications';
export {
  setupWizardStore,
  nextStep,
  prevStep,
  resetSetupWizard,
} from './stores/setup-wizard.svelte';
export type {
  SetupWizardStep,
  SetupWizardState,
  BarrierStrategy,
} from './stores/setup-wizard.svelte';

// Utils
export * from './utils/formatters';
export * from './utils/validators';
