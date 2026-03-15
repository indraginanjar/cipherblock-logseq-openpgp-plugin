// CipherBlock – UI Module
// Renders dialogs for recipient selection, key selection, and passphrase input.

import type { StoredKey, OutputMode } from './types';

const DIALOG_CONTAINER_ID = 'cipherblock-dialog-container';

/** Shared CSS for all CipherBlock dialogs. */
const DIALOG_STYLES = `
  .cipherblock-overlay {
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.5); display: flex; align-items: center;
    justify-content: center; z-index: 9999;
  }
  .cipherblock-dialog {
    background: var(--ls-primary-background-color, #fff);
    color: var(--ls-primary-text-color, #333);
    border-radius: 8px; padding: 20px; min-width: 380px; max-width: 500px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.25); font-family: inherit;
  }
  .cipherblock-dialog h3 {
    margin: 0 0 14px 0; font-size: 16px;
  }
  .cipherblock-dialog label {
    display: flex; align-items: center; gap: 8px; padding: 4px 0;
    font-size: 13px; cursor: pointer;
  }
  .cipherblock-dialog .cb-key-list {
    max-height: 200px; overflow-y: auto; margin-bottom: 12px;
    border: 1px solid var(--ls-border-color, #ddd); border-radius: 4px; padding: 6px;
  }
  .cipherblock-dialog select, .cipherblock-dialog input[type="password"] {
    width: 100%; padding: 6px 8px; border: 1px solid var(--ls-border-color, #ddd);
    border-radius: 4px; font-size: 13px; box-sizing: border-box;
    background: var(--ls-secondary-background-color, #f5f5f5);
    color: var(--ls-primary-text-color, #333);
  }
  .cipherblock-dialog .cb-field { margin-bottom: 12px; }
  .cipherblock-dialog .cb-field-label {
    font-size: 12px; font-weight: 600; margin-bottom: 4px; display: block;
  }
  .cipherblock-dialog .cb-buttons {
    display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px;
  }
  .cipherblock-dialog button {
    padding: 6px 16px; border-radius: 4px; border: 1px solid var(--ls-border-color, #ddd);
    cursor: pointer; font-size: 13px;
    background: var(--ls-secondary-background-color, #f5f5f5);
    color: var(--ls-primary-text-color, #333);
  }
  .cipherblock-dialog button.cb-primary {
    background: var(--ls-link-text-color, #045591);
    color: #fff; border-color: transparent;
  }
`;

/** Remove the dialog container from the DOM. */
function cleanupDialog(): void {
  const el = parent.document.getElementById(DIALOG_CONTAINER_ID);
  if (el) {
    el.remove();
  }
}

/** Truncate a fingerprint for display (first 4 + last 4 hex chars). */
function shortFingerprint(fp: string): string {
  if (fp.length <= 16) return fp;
  return fp.slice(0, 8) + '…' + fp.slice(-8);
}

/**
 * Show a dialog for selecting encryption recipients and output mode.
 *
 * Renders checkboxes for each public key and a dropdown for output mode.
 * Returns the selected fingerprints and output mode, or null if cancelled.
 *
 * @param publicKeys - Available public keys to choose from
 * @param currentOutputMode - The currently configured output mode (pre-selected)
 * @returns Selected recipients and output mode, or null if cancelled
 */
export function showRecipientDialog(
  publicKeys: StoredKey[],
  currentOutputMode: OutputMode,
): Promise<{ recipients: string[]; outputMode: OutputMode } | null> {
  return new Promise((resolve) => {
    cleanupDialog();

    const keyCheckboxes = publicKeys
      .map(
        (k, i) =>
          `<label>
            <input type="checkbox" name="cb-recipient" value="${k.fingerprint}" data-index="${i}" />
            <span>${shortFingerprint(k.fingerprint)} – ${escapeHtml(k.userID)}</span>
          </label>`,
      )
      .join('');

    const outputOptions: OutputMode[] = ['replace', 'sibling', 'sub-block', 'clipboard'];
    const outputSelect = outputOptions
      .map(
        (m) =>
          `<option value="${m}"${m === currentOutputMode ? ' selected' : ''}>${m}</option>`,
      )
      .join('');

    const html = `
      <style>${DIALOG_STYLES}</style>
      <div class="cipherblock-overlay" id="cipherblock-recipient-overlay">
        <div class="cipherblock-dialog">
          <h3>Select Recipients</h3>
          <div class="cb-key-list">${keyCheckboxes || '<em>No public keys available</em>'}</div>
          <div class="cb-field">
            <span class="cb-field-label">Output Mode</span>
            <select id="cipherblock-output-mode">${outputSelect}</select>
          </div>
          <div class="cb-buttons">
            <button id="cipherblock-cancel-btn">Cancel</button>
            <button id="cipherblock-ok-btn" class="cb-primary">Encrypt</button>
          </div>
        </div>
      </div>
    `;

    injectDialog(html);

    const doc = parent.document;

    const onOk = () => {
      const checked = Array.from(
        doc.querySelectorAll<HTMLInputElement>('input[name="cb-recipient"]:checked'),
      ).map((el) => el.value);
      const modeEl = doc.getElementById('cipherblock-output-mode') as HTMLSelectElement | null;
      const outputMode = (modeEl?.value ?? currentOutputMode) as OutputMode;
      cleanup();
      resolve(checked.length > 0 ? { recipients: checked, outputMode } : null);
    };

    const onCancel = () => {
      cleanup();
      resolve(null);
    };

    const onOverlayClick = (e: Event) => {
      if ((e.target as HTMLElement).id === 'cipherblock-recipient-overlay') {
        onCancel();
      }
    };

    function cleanup() {
      doc.getElementById('cipherblock-ok-btn')?.removeEventListener('click', onOk);
      doc.getElementById('cipherblock-cancel-btn')?.removeEventListener('click', onCancel);
      doc.getElementById('cipherblock-recipient-overlay')?.removeEventListener('click', onOverlayClick);
      cleanupDialog();
    }

    doc.getElementById('cipherblock-ok-btn')?.addEventListener('click', onOk);
    doc.getElementById('cipherblock-cancel-btn')?.addEventListener('click', onCancel);
    doc.getElementById('cipherblock-recipient-overlay')?.addEventListener('click', onOverlayClick);
  });
}

/**
 * Show a dialog for selecting a private key for decryption.
 *
 * Renders radio buttons for each private key.
 * Returns the selected fingerprint, or null if cancelled.
 *
 * @param privateKeys - Available private keys to choose from
 * @returns Selected fingerprint, or null if cancelled
 */
export function showKeySelectionDialog(
  privateKeys: StoredKey[],
): Promise<string | null> {
  return new Promise((resolve) => {
    cleanupDialog();

    const keyRadios = privateKeys
      .map(
        (k, i) =>
          `<label>
            <input type="radio" name="cb-privkey" value="${k.fingerprint}" ${i === 0 ? 'checked' : ''} />
            <span>${shortFingerprint(k.fingerprint)} – ${escapeHtml(k.userID)}</span>
          </label>`,
      )
      .join('');

    const html = `
      <style>${DIALOG_STYLES}</style>
      <div class="cipherblock-overlay" id="cipherblock-key-overlay">
        <div class="cipherblock-dialog">
          <h3>Select Private Key</h3>
          <div class="cb-key-list">${keyRadios || '<em>No private keys available</em>'}</div>
          <div class="cb-buttons">
            <button id="cipherblock-cancel-btn">Cancel</button>
            <button id="cipherblock-ok-btn" class="cb-primary">Decrypt</button>
          </div>
        </div>
      </div>
    `;

    injectDialog(html);

    const doc = parent.document;

    const onOk = () => {
      const selected = doc.querySelector<HTMLInputElement>('input[name="cb-privkey"]:checked');
      cleanup();
      resolve(selected?.value ?? null);
    };

    const onCancel = () => {
      cleanup();
      resolve(null);
    };

    const onOverlayClick = (e: Event) => {
      if ((e.target as HTMLElement).id === 'cipherblock-key-overlay') {
        onCancel();
      }
    };

    function cleanup() {
      doc.getElementById('cipherblock-ok-btn')?.removeEventListener('click', onOk);
      doc.getElementById('cipherblock-cancel-btn')?.removeEventListener('click', onCancel);
      doc.getElementById('cipherblock-key-overlay')?.removeEventListener('click', onOverlayClick);
      cleanupDialog();
    }

    doc.getElementById('cipherblock-ok-btn')?.addEventListener('click', onOk);
    doc.getElementById('cipherblock-cancel-btn')?.addEventListener('click', onCancel);
    doc.getElementById('cipherblock-key-overlay')?.addEventListener('click', onOverlayClick);
  });
}

/**
 * Show a passphrase input dialog.
 *
 * Renders a password input field. Returns the entered passphrase string.
 * Throws if the user cancels.
 *
 * @returns The entered passphrase
 * @throws Error if the user cancels the dialog
 */
export function showPassphrasePrompt(): Promise<string> {
  return new Promise((resolve, reject) => {
    cleanupDialog();

    const html = `
      <style>${DIALOG_STYLES}</style>
      <div class="cipherblock-overlay" id="cipherblock-passphrase-overlay">
        <div class="cipherblock-dialog">
          <h3>Enter Passphrase</h3>
          <div class="cb-field">
            <span class="cb-field-label">Passphrase for private key</span>
            <input type="password" id="cipherblock-passphrase-input" placeholder="Enter passphrase…" autocomplete="off" />
          </div>
          <div class="cb-buttons">
            <button id="cipherblock-cancel-btn">Cancel</button>
            <button id="cipherblock-ok-btn" class="cb-primary">OK</button>
          </div>
        </div>
      </div>
    `;

    injectDialog(html);

    const doc = parent.document;
    const input = doc.getElementById('cipherblock-passphrase-input') as HTMLInputElement | null;
    input?.focus();

    const onOk = () => {
      const value = input?.value ?? '';
      cleanup();
      resolve(value);
    };

    const onCancel = () => {
      cleanup();
      reject(new Error('Passphrase entry cancelled'));
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Enter') onOk();
      if (e.key === 'Escape') onCancel();
    };

    const onOverlayClick = (e: Event) => {
      if ((e.target as HTMLElement).id === 'cipherblock-passphrase-overlay') {
        onCancel();
      }
    };

    function cleanup() {
      doc.getElementById('cipherblock-ok-btn')?.removeEventListener('click', onOk);
      doc.getElementById('cipherblock-cancel-btn')?.removeEventListener('click', onCancel);
      input?.removeEventListener('keydown', onKeyDown as EventListener);
      doc.getElementById('cipherblock-passphrase-overlay')?.removeEventListener('click', onOverlayClick);
      cleanupDialog();
    }

    doc.getElementById('cipherblock-ok-btn')?.addEventListener('click', onOk);
    doc.getElementById('cipherblock-cancel-btn')?.addEventListener('click', onCancel);
    input?.addEventListener('keydown', onKeyDown as EventListener);
    doc.getElementById('cipherblock-passphrase-overlay')?.addEventListener('click', onOverlayClick);
  });
}

/** Inject dialog HTML into the parent document. */
function injectDialog(html: string): void {
  const container = parent.document.createElement('div');
  container.id = DIALOG_CONTAINER_ID;
  container.innerHTML = html;
  parent.document.body.appendChild(container);
}

/** Escape HTML special characters to prevent XSS in user IDs. */
function escapeHtml(str: string): string {
  return str
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

/**
 * Show a dialog for importing an armored OpenPGP key.
 *
 * Provides two ways to import: paste armored text or pick a .asc/.gpg file.
 * Returns the armored key string, or null if cancelled.
 */
export function showImportKeyDialog(): Promise<string | null> {
  return new Promise((resolve) => {
    cleanupDialog();

    const html = `
      <style>${DIALOG_STYLES}
        .cipherblock-dialog textarea {
          width: 100%; min-height: 140px; padding: 8px;
          border: 1px solid var(--ls-border-color, #ddd); border-radius: 4px;
          font-family: monospace; font-size: 12px; box-sizing: border-box;
          background: var(--ls-secondary-background-color, #f5f5f5);
          color: var(--ls-primary-text-color, #333); resize: vertical;
        }
        .cipherblock-dialog .cb-or-divider {
          text-align: center; margin: 10px 0; font-size: 12px; opacity: 0.6;
        }
        .cipherblock-dialog .cb-file-row {
          display: flex; align-items: center; gap: 8px;
        }
        .cipherblock-dialog .cb-file-row label {
          display: inline-flex; padding: 6px 14px; border-radius: 4px;
          border: 1px solid var(--ls-border-color, #ddd); cursor: pointer;
          font-size: 13px; background: var(--ls-secondary-background-color, #f5f5f5);
        }
        .cipherblock-dialog .cb-file-name {
          font-size: 12px; opacity: 0.7; overflow: hidden;
          text-overflow: ellipsis; white-space: nowrap;
        }
      </style>
      <div class="cipherblock-overlay" id="cipherblock-import-overlay">
        <div class="cipherblock-dialog">
          <h3>Import OpenPGP Key</h3>
          <div class="cb-field">
            <span class="cb-field-label">Pick a key file (.asc, .gpg, .pub, .key)</span>
            <div class="cb-file-row">
              <label for="cipherblock-file-input">Choose File</label>
              <input type="file" id="cipherblock-file-input" accept=".asc,.gpg,.pub,.key,.txt" style="display:none;" />
              <span class="cb-file-name" id="cipherblock-file-name">No file selected</span>
            </div>
          </div>
          <div class="cb-or-divider">— or paste armored key —</div>
          <div class="cb-field">
            <textarea id="cipherblock-import-textarea"
              placeholder="-----BEGIN PGP PUBLIC KEY BLOCK-----&#10;...&#10;-----END PGP PUBLIC KEY BLOCK-----"></textarea>
          </div>
          <div class="cb-buttons">
            <button id="cipherblock-cancel-btn">Cancel</button>
            <button id="cipherblock-ok-btn" class="cb-primary">Import</button>
          </div>
        </div>
      </div>
    `;

    injectDialog(html);

    const doc = parent.document;
    const textarea = doc.getElementById('cipherblock-import-textarea') as HTMLTextAreaElement | null;
    const fileInput = doc.getElementById('cipherblock-file-input') as HTMLInputElement | null;
    const fileNameSpan = doc.getElementById('cipherblock-file-name') as HTMLSpanElement | null;

    // When a file is picked, read it and populate the textarea
    const onFileChange = () => {
      const file = fileInput?.files?.[0];
      if (!file) return;
      if (fileNameSpan) fileNameSpan.textContent = file.name;
      const reader = new FileReader();
      reader.onload = () => {
        if (textarea && typeof reader.result === 'string') {
          textarea.value = reader.result;
        }
      };
      reader.readAsText(file);
    };

    fileInput?.addEventListener('change', onFileChange);

    const onOk = () => {
      const value = textarea?.value?.trim() ?? '';
      cleanup();
      resolve(value.length > 0 ? value : null);
    };

    const onCancel = () => {
      cleanup();
      resolve(null);
    };

    const onOverlayClick = (e: Event) => {
      if ((e.target as HTMLElement).id === 'cipherblock-import-overlay') {
        onCancel();
      }
    };

    function cleanup() {
      doc.getElementById('cipherblock-ok-btn')?.removeEventListener('click', onOk);
      doc.getElementById('cipherblock-cancel-btn')?.removeEventListener('click', onCancel);
      doc.getElementById('cipherblock-import-overlay')?.removeEventListener('click', onOverlayClick);
      fileInput?.removeEventListener('change', onFileChange);
      cleanupDialog();
    }

    doc.getElementById('cipherblock-ok-btn')?.addEventListener('click', onOk);
    doc.getElementById('cipherblock-cancel-btn')?.addEventListener('click', onCancel);
    doc.getElementById('cipherblock-import-overlay')?.addEventListener('click', onOverlayClick);
  });
}

/**
 * Show a dialog listing all stored keys with the ability to remove them.
 *
 * @param keys - All stored keys to display
 * @returns Fingerprint of the key to remove, or null if cancelled/closed
 */
export function showKeyManagerDialog(
  keys: StoredKey[],
): Promise<string | null> {
  return new Promise((resolve) => {
    cleanupDialog();

    const keyRows = keys
      .map(
        (k) =>
          `<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--ls-border-color,#eee);">
            <div style="font-size:13px;">
              <span style="font-weight:600;">${escapeHtml(k.userID || 'No User ID')}</span><br/>
              <span style="font-size:11px;opacity:0.7;">${shortFingerprint(k.fingerprint)} · ${k.type}</span>
            </div>
            <button class="cb-remove-key-btn" data-fp="${k.fingerprint}"
              style="padding:3px 10px;font-size:12px;color:#d33;border-color:#d33;background:transparent;cursor:pointer;border-radius:4px;border:1px solid #d33;">
              Remove
            </button>
          </div>`,
      )
      .join('');

    const html = `
      <style>${DIALOG_STYLES}</style>
      <div class="cipherblock-overlay" id="cipherblock-keymgr-overlay">
        <div class="cipherblock-dialog">
          <h3>Manage Keys (${keys.length})</h3>
          <div class="cb-key-list" style="max-height:300px;">
            ${keyRows || '<em style="padding:8px;display:block;">No keys imported yet</em>'}
          </div>
          <div class="cb-buttons">
            <button id="cipherblock-close-btn" class="cb-primary">Close</button>
          </div>
        </div>
      </div>
    `;

    injectDialog(html);

    const doc = parent.document;

    const onClose = () => {
      cleanup();
      resolve(null);
    };

    const onOverlayClick = (e: Event) => {
      if ((e.target as HTMLElement).id === 'cipherblock-keymgr-overlay') {
        onClose();
      }
    };

    const onRemoveClick = (e: Event) => {
      const btn = (e.target as HTMLElement).closest('.cb-remove-key-btn') as HTMLElement | null;
      if (btn) {
        const fp = btn.getAttribute('data-fp');
        cleanup();
        resolve(fp);
      }
    };

    function cleanup() {
      doc.getElementById('cipherblock-close-btn')?.removeEventListener('click', onClose);
      doc.getElementById('cipherblock-keymgr-overlay')?.removeEventListener('click', onOverlayClick);
      const list = doc.querySelector(`#${DIALOG_CONTAINER_ID} .cb-key-list`);
      list?.removeEventListener('click', onRemoveClick);
      cleanupDialog();
    }

    doc.getElementById('cipherblock-close-btn')?.addEventListener('click', onClose);
    doc.getElementById('cipherblock-keymgr-overlay')?.addEventListener('click', onOverlayClick);
    const list = doc.querySelector(`#${DIALOG_CONTAINER_ID} .cb-key-list`);
    list?.addEventListener('click', onRemoveClick);
  });
}
