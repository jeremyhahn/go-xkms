"use strict";
// xKey AutoFill Extension - Popup Logic
//
// Runs in the extension popup context. Communicates with the background
// service worker to search credentials and display results.
//
// Self-contained: no ES module imports (loaded via <script> in popup.html).
/// <reference types="chrome" />
// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let currentTOTP = null;
let totpInterval = null;
let pairingActive = false;
// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------
function getEl(id) {
    const el = document.getElementById(id);
    if (!el)
        throw new Error(`Element not found: ${id}`);
    return el;
}
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------
async function init() {
    // Wire up pairing submit handler.
    initPairing();
    initUnlock();
    // Determine current tab domain.
    let domain = '';
    try {
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];
        if (tab?.url) {
            const url = new URL(tab.url);
            domain = url.hostname;
        }
    }
    catch {
        // No access to tab URL (e.g., chrome:// pages).
    }
    getEl('current-domain').textContent = domain || 'No site';
    // Check connection status (also triggers connect if needed).
    let statusResp;
    try {
        statusResp = await chrome.runtime.sendMessage({ type: 'status' });
    }
    catch (err) {
        statusResp = { type: 'error', message: String(err) };
    }
    // Check if pairing is required.
    if (statusResp.type === 'pairing_status' && statusResp.required) {
        showPairingSection();
        return;
    }
    updateStatus(statusResp);
    // If error or locked, stop here.
    if (statusResp.type === 'error') {
        showConnectButton();
        return;
    }
    if (statusResp.data?.app_locked) {
        showUnlockSection();
        return;
    }
    if (!domain)
        return;
    // Search for credentials matching this domain.
    try {
        const searchResp = await chrome.runtime.sendMessage({ type: 'search', domain });
        if (searchResp.type === 'pairing_status') {
            showPairingSection();
            return;
        }
        if (searchResp.type === 'credentials') {
            renderCredentials(searchResp.data);
        }
        else if (searchResp.type === 'error') {
            showError(searchResp.message);
        }
    }
    catch (err) {
        showError(String(err));
    }
    // Check for TOTP codes for this domain.
    try {
        const totpResp = await chrome.runtime.sendMessage({ type: 'totp', domain });
        if (totpResp.type === 'totp_result' && totpResp.data) {
            showTOTP(totpResp.data);
        }
    }
    catch {
        // TOTP lookup is best-effort.
    }
}
// ---------------------------------------------------------------------------
// Status display
// ---------------------------------------------------------------------------
function updateStatus(resp) {
    const dot = getEl('status-dot');
    const text = getEl('status-text');
    if (resp.type === 'error') {
        dot.className = 'status-dot disconnected';
        text.textContent = 'Not connected';
        return;
    }
    const status = resp.data;
    if (!status) {
        dot.className = 'status-dot disconnected';
        text.textContent = 'Unknown';
        return;
    }
    if (status.app_locked) {
        dot.className = 'status-dot locked';
        text.textContent = 'App locked - unlock xKey to continue';
    }
    else if (status.available && status.extension_enabled) {
        dot.className = 'status-dot connected';
        text.textContent = 'Connected';
    }
    else if (!status.extension_enabled) {
        dot.className = 'status-dot disconnected';
        text.textContent = 'AutoFill disabled in xKey settings';
    }
    else {
        dot.className = 'status-dot disconnected';
        text.textContent = 'Unavailable';
    }
}
// ---------------------------------------------------------------------------
// Credential list
// ---------------------------------------------------------------------------
function renderCredentials(credentials) {
    const list = getEl('credentials-list');
    if (credentials.length === 0) {
        list.innerHTML = '<div class="empty-state">No credentials found for this site</div>';
        return;
    }
    list.innerHTML = '';
    for (const cred of credentials) {
        const item = document.createElement('div');
        item.className = 'credential-item';
        // Credential info
        const info = document.createElement('div');
        info.className = 'cred-info';
        const title = document.createElement('span');
        title.className = 'cred-title';
        title.textContent = cred.title || cred.username;
        const username = document.createElement('span');
        username.className = 'cred-username';
        username.textContent = cred.username;
        info.appendChild(title);
        info.appendChild(username);
        // Actions
        const actions = document.createElement('div');
        actions.className = 'cred-actions';
        const fillBtn = document.createElement('button');
        fillBtn.className = 'btn btn-fill';
        fillBtn.textContent = 'Fill';
        fillBtn.addEventListener('click', () => handleFill(cred));
        actions.appendChild(fillBtn);
        // TOTP button if available
        if (cred.has_totp && cred.totp_id) {
            const totpBtn = document.createElement('button');
            totpBtn.className = 'btn';
            totpBtn.textContent = 'TOTP';
            totpBtn.title = 'Show TOTP code';
            totpBtn.addEventListener('click', () => handleTOTP(cred.totp_id));
            actions.appendChild(totpBtn);
        }
        item.appendChild(info);
        item.appendChild(actions);
        list.appendChild(item);
    }
}
// ---------------------------------------------------------------------------
// Fill action
// ---------------------------------------------------------------------------
async function handleFill(cred) {
    try {
        const resp = await chrome.runtime.sendMessage({ type: 'fill', id: cred.id });
        if (resp.type === 'fill_result' && resp.data) {
            // Send fill data to the content script for injection.
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs[0]?.id !== undefined) {
                await chrome.tabs.sendMessage(tabs[0].id, {
                    type: 'fill_from_popup',
                    data: resp.data,
                });
            }
            window.close();
        }
        else if (resp.type === 'error') {
            showError(resp.message);
        }
    }
    catch (err) {
        showError(String(err));
    }
}
// ---------------------------------------------------------------------------
// TOTP display
// ---------------------------------------------------------------------------
async function handleTOTP(totpId) {
    try {
        const resp = await chrome.runtime.sendMessage({ type: 'totp_by_id', id: totpId });
        if (resp.type === 'totp_result' && resp.data) {
            showTOTP(resp.data);
        }
        else if (resp.type === 'error') {
            showError(resp.message);
        }
    }
    catch (err) {
        showError(String(err));
    }
}
function showTOTP(totp) {
    currentTOTP = totp;
    const section = getEl('totp-section');
    const codeEl = getEl('totp-code');
    const timerEl = getEl('totp-timer');
    const issuerEl = getEl('totp-issuer');
    section.style.display = 'block';
    codeEl.textContent = formatTOTPCode(totp.code);
    timerEl.textContent = `${totp.time_left}s remaining`;
    issuerEl.textContent = totp.issuer || '';
    // Update countdown timer.
    if (totpInterval) {
        clearInterval(totpInterval);
        totpInterval = null;
    }
    let timeLeft = totp.time_left;
    totpInterval = setInterval(async () => {
        timeLeft--;
        if (timeLeft <= 0) {
            // Refresh the TOTP code.
            try {
                const resp = await chrome.runtime.sendMessage({
                    type: 'totp_by_id',
                    id: totp.account_id,
                });
                if (resp.type === 'totp_result' && resp.data) {
                    showTOTP(resp.data);
                }
            }
            catch {
                // Refresh failed; leave stale display.
            }
        }
        else {
            timerEl.textContent = `${timeLeft}s remaining`;
        }
    }, 1000);
    // Wire up copy button.
    const copyBtn = getEl('totp-copy');
    copyBtn.onclick = () => {
        if (currentTOTP) {
            navigator.clipboard.writeText(currentTOTP.code).then(() => {
                copyBtn.textContent = 'Copied';
                setTimeout(() => {
                    copyBtn.textContent = 'Copy';
                }, 1500);
            });
        }
    };
}
/**
 * Format a TOTP code with a space in the middle for readability.
 * "123456" -> "123 456"
 */
function formatTOTPCode(code) {
    if (code.length === 6) {
        return code.slice(0, 3) + ' ' + code.slice(3);
    }
    if (code.length === 8) {
        return code.slice(0, 4) + ' ' + code.slice(4);
    }
    return code;
}
// ---------------------------------------------------------------------------
// Error display
// ---------------------------------------------------------------------------
function showError(message) {
    const container = getEl('error-container');
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-state';
    errorDiv.textContent = message;
    container.innerHTML = '';
    container.appendChild(errorDiv);
}
// ---------------------------------------------------------------------------
// Pairing flow
// ---------------------------------------------------------------------------
/**
 * Initialize the pairing submit button event listener.
 */
function initPairing() {
    const submitBtn = document.getElementById('pairing-submit');
    if (submitBtn) {
        submitBtn.addEventListener('click', handlePairingSubmit);
    }
    const retryBtn = document.getElementById('pairing-retry');
    if (retryBtn) {
        retryBtn.addEventListener('click', handlePairingRetry);
    }
    const codeInput = document.getElementById('pairing-code');
    if (codeInput) {
        // Allow Enter key to submit.
        codeInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                handlePairingSubmit();
            }
        });
        // Filter non-numeric input.
        codeInput.addEventListener('input', () => {
            codeInput.value = codeInput.value.replace(/[^0-9]/g, '');
        });
    }
}
/**
 * Show the pairing section and hide credential-related UI.
 */
function showPairingSection() {
    pairingActive = true;
    const pairingSection = document.getElementById('pairing-section');
    const credentialsList = document.getElementById('credentials-list');
    const totpSection = document.getElementById('totp-section');
    if (pairingSection)
        pairingSection.style.display = 'block';
    if (credentialsList)
        credentialsList.style.display = 'none';
    if (totpSection)
        totpSection.style.display = 'none';
    // Update status to show pairing state.
    const dot = getEl('status-dot');
    const text = getEl('status-text');
    dot.className = 'status-dot locked';
    text.textContent = 'Pairing required';
    // Focus the code input.
    const codeInput = document.getElementById('pairing-code');
    if (codeInput) {
        setTimeout(() => codeInput.focus(), 100);
    }
}
/**
 * Hide the pairing section and restore credential UI.
 */
function hidePairingSection() {
    pairingActive = false;
    const pairingSection = document.getElementById('pairing-section');
    const credentialsList = document.getElementById('credentials-list');
    if (pairingSection)
        pairingSection.style.display = 'none';
    if (credentialsList)
        credentialsList.style.display = 'block';
}
/**
 * Handle pairing code submission.
 * Sends the code to the background service worker which forwards it
 * to the native host for verification.
 */
async function handlePairingSubmit() {
    const codeInput = document.getElementById('pairing-code');
    const errorEl = document.getElementById('pairing-error');
    const successEl = document.getElementById('pairing-success');
    const submitBtn = document.getElementById('pairing-submit');
    if (!codeInput)
        return;
    const code = codeInput.value.trim();
    if (code.length !== 6 || !/^\d{6}$/.test(code)) {
        if (errorEl) {
            errorEl.textContent = 'Please enter a 6-digit code';
            errorEl.style.display = 'block';
        }
        return;
    }
    // Hide any previous error, disable submit.
    if (errorEl)
        errorEl.style.display = 'none';
    if (successEl)
        successEl.style.display = 'none';
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Pairing...';
    }
    try {
        const resp = await chrome.runtime.sendMessage({
            type: 'pairing_submit',
            code,
        });
        if (resp.type === 'pairing_ok') {
            // Pairing succeeded.
            if (successEl)
                successEl.style.display = 'block';
            if (codeInput)
                codeInput.disabled = true;
            // After a brief delay, hide pairing and reload credentials.
            setTimeout(() => {
                hidePairingSection();
                // Re-initialize to load credentials.
                init();
            }, 1000);
        }
        else {
            // Pairing failed — background has already disconnected and reset state.
            // Show error and retry button so the user can start a fresh connection.
            const errMsg = resp.error || 'Pairing failed. Please try again.';
            if (errorEl) {
                errorEl.textContent = errMsg;
                errorEl.style.display = 'block';
            }
            const retryBtn = document.getElementById('pairing-retry');
            if (retryBtn)
                retryBtn.style.display = 'block';
            codeInput.value = '';
            codeInput.focus();
        }
    }
    catch (err) {
        if (errorEl) {
            errorEl.textContent = String(err);
            errorEl.style.display = 'block';
        }
    }
    finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Pair';
        }
    }
}
/**
 * Handle the "Retry Connection" button.
 * Sends pairing_cancel to the background to reset state, then re-initializes.
 */
async function handlePairingRetry() {
    const retryBtn = document.getElementById('pairing-retry');
    const errorEl = document.getElementById('pairing-error');
    const codeInput = document.getElementById('pairing-code');
    // Reset UI.
    if (retryBtn)
        retryBtn.style.display = 'none';
    if (errorEl)
        errorEl.style.display = 'none';
    if (codeInput) {
        codeInput.value = '';
        codeInput.disabled = false;
    }
    // Tell background to reset pairing state.
    try {
        await chrome.runtime.sendMessage({ type: 'pairing_cancel' });
    }
    catch {
        // Best-effort.
    }
    // Hide pairing section and re-run init for a fresh connection attempt.
    hidePairingSection();
    init();
}
// ---------------------------------------------------------------------------
// Unlock flow
// ---------------------------------------------------------------------------
/**
 * Initialize the unlock submit button event listener.
 */
function initUnlock() {
    const submitBtn = document.getElementById('unlock-submit');
    if (submitBtn) {
        submitBtn.addEventListener('click', handleUnlockSubmit);
    }
    const pinInput = document.getElementById('unlock-pin');
    if (pinInput) {
        pinInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                handleUnlockSubmit();
            }
        });
    }
}
/**
 * Show the unlock section and hide credential-related UI.
 */
function showUnlockSection() {
    const unlockSection = document.getElementById('unlock-section');
    const credentialsList = document.getElementById('credentials-list');
    const totpSection = document.getElementById('totp-section');
    if (unlockSection)
        unlockSection.style.display = 'block';
    if (credentialsList)
        credentialsList.style.display = 'none';
    if (totpSection)
        totpSection.style.display = 'none';
    // Focus the PIN input.
    const pinInput = document.getElementById('unlock-pin');
    if (pinInput) {
        setTimeout(() => pinInput.focus(), 100);
    }
}
/**
 * Hide the unlock section and restore credential UI.
 */
function hideUnlockSection() {
    const unlockSection = document.getElementById('unlock-section');
    const credentialsList = document.getElementById('credentials-list');
    if (unlockSection)
        unlockSection.style.display = 'none';
    if (credentialsList)
        credentialsList.style.display = 'block';
}
/**
 * Handle unlock PIN submission.
 */
async function handleUnlockSubmit() {
    const pinInput = document.getElementById('unlock-pin');
    const errorEl = document.getElementById('unlock-error');
    const submitBtn = document.getElementById('unlock-submit');
    if (!pinInput)
        return;
    const pin = pinInput.value;
    if (!pin) {
        if (errorEl) {
            errorEl.textContent = 'Please enter your PIN';
            errorEl.style.display = 'block';
        }
        return;
    }
    // Hide any previous error, disable submit.
    if (errorEl)
        errorEl.style.display = 'none';
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Unlocking...';
    }
    try {
        const resp = await chrome.runtime.sendMessage({
            type: 'unlock',
            pin,
        });
        if (resp.type === 'unlock_result' && resp.success) {
            // Unlock succeeded — hide unlock section and re-initialize.
            hideUnlockSection();
            pinInput.value = '';
            init();
        }
        else {
            // Prefer unlock-specific error, then generic error/message fields.
            const errMsg = resp.error || resp.message || 'Invalid PIN';
            if (errorEl) {
                errorEl.textContent = errMsg;
                errorEl.style.display = 'block';
            }
            pinInput.value = '';
            pinInput.focus();
        }
    }
    catch (err) {
        if (errorEl) {
            errorEl.textContent = String(err);
            errorEl.style.display = 'block';
        }
    }
    finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Unlock';
        }
    }
}
// ---------------------------------------------------------------------------
// Reconnect flow
// ---------------------------------------------------------------------------
/**
 * Show a "Connect" button in the status bar so the user can manually
 * trigger a reconnect after xKey restarts.
 */
function showConnectButton() {
    const statusBar = document.getElementById('status-bar');
    if (!statusBar)
        return;
    // Avoid adding a duplicate button if one already exists.
    if (document.getElementById('connect-btn'))
        return;
    const btn = document.createElement('button');
    btn.id = 'connect-btn';
    btn.textContent = 'Connect';
    btn.addEventListener('click', handleConnect);
    statusBar.appendChild(btn);
}
/**
 * Handle the "Connect" button click.
 * Sends a reconnect message to the background and refreshes the popup on success.
 */
async function handleConnect() {
    const btn = document.getElementById('connect-btn');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Connecting...';
    }
    try {
        const resp = await chrome.runtime.sendMessage({ type: 'reconnect' });
        if (resp.type === 'reconnect_result' && resp.connected) {
            btn?.remove();
            if (resp.locked) {
                showUnlockSection();
            }
            init();
        }
        else {
            const errMsg = resp.message || 'Could not connect to xKey';
            showError(errMsg);
            if (btn) {
                btn.textContent = 'Retry';
            }
        }
    }
    catch (err) {
        showError(String(err));
        if (btn) {
            btn.textContent = 'Retry';
        }
    }
    finally {
        if (btn) {
            btn.disabled = false;
        }
    }
}
// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
init();
//# sourceMappingURL=popup.js.map