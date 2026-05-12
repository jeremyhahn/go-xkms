/**
 * downloadPEM triggers a browser file download for a PEM-encoded payload.
 * Works in both Vite preview and Wails (Wails exposes a standard browser
 * runtime for the frontend, so Blob + object URLs work identically).
 *
 * The anchor MUST be appended to the DOM before click() in Chromium, and the
 * object URL MUST be revoked on a later tick — revoking synchronously after
 * click() cancels the in-flight download.
 */
export function downloadPEM(filename: string, pem: string): void {
  const blob = new Blob([pem], { type: 'application/x-pem-file' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  // Defer cleanup so Chromium has time to start the download.
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 0);
}
