// CipherBlock – Unit tests for UI Module
// Test framework: Vitest
// Source: src/ui.ts

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { StoredKey } from './types';
import {
  showRecipientDialog,
  showKeySelectionDialog,
  showPassphrasePrompt,
} from './ui';

// --- DOM helpers ---

/** Minimal helper: create a real DOM environment via JSDOM-like globals.
 *  The UI module injects HTML into `parent.document`, so we point `parent`
 *  at the current `globalThis` and use Vitest's built-in DOM (or a light shim). */

let dialogContainer: HTMLDivElement | null = null;

function setupParentDocument(): void {
  // The ui.ts module accesses `parent.document`. In a test env `parent === globalThis`.
  // We need a real-ish document. Vitest runs in Node, so we build a minimal shim.

  const body: any = {
    appendChild(child: any) {
      dialogContainer = child;
    },
  };

  // We'll use a different approach: intercept injectDialog by providing a
  // parent.document that creates a real-enough container from innerHTML.
  const listeners = new Map<string, Map<string, Function[]>>();

  function addListenerFor(id: string, event: string, fn: Function) {
    if (!listeners.has(id)) listeners.set(id, new Map());
    const elMap = listeners.get(id)!;
    if (!elMap.has(event)) elMap.set(event, []);
    elMap.get(event)!.push(fn);
  }

  function removeListenerFor(id: string, event: string, fn: Function) {
    const elMap = listeners.get(id);
    if (!elMap) return;
    const arr = elMap.get(event);
    if (!arr) return;
    const idx = arr.indexOf(fn);
    if (idx >= 0) arr.splice(idx, 1);
  }

  function fireEvent(id: string, event: string, eventObj?: any) {
    const elMap = listeners.get(id);
    if (!elMap) return;
    const arr = elMap.get(event);
    if (!arr) return;
    for (const fn of arr) fn(eventObj ?? { target: { id } });
  }

  // Store injected HTML so we can query it
  let injectedHTML = '';
  // Track checkbox/radio/input values
  const inputValues = new Map<string, { checked: boolean; value: string; type: string; name: string }>();
  let selectValue = '';

  const fakeDocument: any = {
    createElement(tag: string) {
      const el: any = Object.create(null, {
        id: { value: '', writable: true, enumerable: true },
        tagName: { value: tag.toUpperCase(), enumerable: true },
        style: { value: {}, enumerable: true },
        dataset: { value: {}, enumerable: true },
        children: { value: [], enumerable: true },
        appendChild: { value() {}, enumerable: true },
        remove: {
          value() {
            dialogContainer = null;
            injectedHTML = '';
            inputValues.clear();
          },
          enumerable: true,
        },
        innerHTML: {
          get() { return injectedHTML; },
          set(html: string) {
            injectedHTML = html;
            parseInputsFromHTML(html);
          },
          enumerable: true,
        },
      });
      return el;
    },
    getElementById(id: string): any {
      if (id === 'cipherblock-dialog-container') {
        return dialogContainer;
      }
      // Return a proxy element that supports addEventListener/removeEventListener
      // and value access for specific known IDs
      if (id === 'cipherblock-output-mode') {
        return {
          id,
          value: selectValue,
          addEventListener: (evt: string, fn: Function) => addListenerFor(id, evt, fn),
          removeEventListener: (evt: string, fn: Function) => removeListenerFor(id, evt, fn),
        };
      }
      if (id === 'cipherblock-passphrase-input') {
        const entry = inputValues.get(id) ?? { checked: false, value: '', type: 'password', name: '' };
        return {
          id,
          get value() { return entry.value; },
          set value(v: string) { entry.value = v; },
          focus: vi.fn(),
          addEventListener: (evt: string, fn: Function) => addListenerFor(id, evt, fn),
          removeEventListener: (evt: string, fn: Function) => removeListenerFor(id, evt, fn),
        };
      }
      // Generic element proxy for buttons and overlays
      return {
        id,
        addEventListener: (evt: string, fn: Function) => addListenerFor(id, evt, fn),
        removeEventListener: (evt: string, fn: Function) => removeListenerFor(id, evt, fn),
      };
    },
    querySelector(selector: string): any {
      // Handle 'input[name="cb-privkey"]:checked'
      if (selector.includes('cb-privkey') && selector.includes(':checked')) {
        for (const [, entry] of inputValues) {
          if (entry.name === 'cb-privkey' && entry.checked) {
            return { value: entry.value };
          }
        }
        return null;
      }
      // Handle '#cipherblock-dialog-container .cb-key-list'
      if (selector.includes('.cb-key-list')) {
        return {
          addEventListener: (evt: string, fn: Function) => addListenerFor('cb-key-list', evt, fn),
          removeEventListener: (evt: string, fn: Function) => removeListenerFor('cb-key-list', evt, fn),
        };
      }
      return null;
    },
    querySelectorAll(selector: string): any[] {
      // Handle 'input[name="cb-recipient"]:checked'
      if (selector.includes('cb-recipient') && selector.includes(':checked')) {
        const results: any[] = [];
        for (const [, entry] of inputValues) {
          if (entry.name === 'cb-recipient' && entry.checked) {
            results.push({ value: entry.value });
          }
        }
        return results;
      }
      return [];
    },
    body,
  };

  function parseInputsFromHTML(html: string): void {
    inputValues.clear();
    // Parse checkboxes: <input type="checkbox" name="cb-recipient" value="FP" ... checked />
    const checkboxRe = /<input\s+type="checkbox"\s+name="([^"]+)"\s+value="([^"]+)"[^>]*>/g;
    let m: RegExpExecArray | null;
    let idx = 0;
    while ((m = checkboxRe.exec(html)) !== null) {
      const fullMatch = m[0];
      // Check if 'checked' appears as a standalone attribute (not inside another word)
      const isChecked = /\bchecked\b/.test(fullMatch);
      inputValues.set(`checkbox-${idx}`, {
        name: m[1],
        value: m[2],
        checked: isChecked,
        type: 'checkbox',
      });
      idx++;
    }
    // Parse radios: <input type="radio" name="cb-privkey" value="FP" checked />
    const radioRe = /<input\s+type="radio"\s+name="([^"]+)"\s+value="([^"]+)"[^>]*>/g;
    while ((m = radioRe.exec(html)) !== null) {
      const fullMatch = m[0];
      const isChecked = /\bchecked\b/.test(fullMatch);
      inputValues.set(`radio-${idx}`, {
        name: m[1],
        value: m[2],
        checked: isChecked,
        type: 'radio',
      });
      idx++;
    }
    // Parse select value
    const selectRe = /<option\s+value="([^"]+)"(\s+selected)?[^>]*>/g;
    while ((m = selectRe.exec(html)) !== null) {
      if (m[2]) selectValue = m[1];
    }
    // Parse password input
    if (html.includes('cipherblock-passphrase-input')) {
      inputValues.set('cipherblock-passphrase-input', {
        name: '',
        value: '',
        checked: false,
        type: 'password',
      });
    }
  }

  // Expose helpers for tests to manipulate state
  (globalThis as any).__testUI = {
    fireEvent,
    setInputChecked(name: string, value: string, checked: boolean) {
      for (const [, entry] of inputValues) {
        if (entry.name === name && entry.value === value) {
          entry.checked = checked;
          return;
        }
      }
    },
    setSelectValue(val: string) {
      selectValue = val;
    },
    setPassphraseValue(val: string) {
      const entry = inputValues.get('cipherblock-passphrase-input');
      if (entry) entry.value = val;
    },
    getInputValues() {
      return inputValues;
    },
  };

  // Point `parent` to an object whose `document` is our fake
  (globalThis as any).parent = { document: fakeDocument };
}

function cleanupParentDocument(): void {
  delete (globalThis as any).parent;
  delete (globalThis as any).__testUI;
  dialogContainer = null;
}

// --- Test data ---

function makePublicKey(fingerprint: string, userID: string): StoredKey {
  return {
    fingerprint,
    userID,
    type: 'public',
    creationDate: new Date('2025-01-01'),
    armoredKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake-${fingerprint}\n-----END PGP PUBLIC KEY BLOCK-----`,
  };
}

function makePrivateKey(fingerprint: string, userID: string): StoredKey {
  return {
    fingerprint,
    userID,
    type: 'private',
    creationDate: new Date('2025-01-01'),
    armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake-${fingerprint}\n-----END PGP PRIVATE KEY BLOCK-----`,
  };
}

// --- Tests ---

describe('UI Module Unit Tests', () => {
  beforeEach(() => {
    setupParentDocument();
  });

  afterEach(() => {
    cleanupParentDocument();
  });

  // **Validates: Requirements 3.1, 5.6**
  describe('showRecipientDialog', () => {
    it('returns selected fingerprints and output mode when user confirms', async () => {
      const keys = [
        makePublicKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice <alice@example.com>'),
        makePublicKey('FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000', 'Bob <bob@example.com>'),
      ];

      const promise = showRecipientDialog(keys, 'replace');

      // Simulate user checking both recipients
      const ui = (globalThis as any).__testUI;
      ui.setInputChecked('cb-recipient', 'AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', true);
      ui.setInputChecked('cb-recipient', 'FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000', true);
      ui.setSelectValue('sibling');

      // Click OK
      ui.fireEvent('cipherblock-ok-btn', 'click');

      const result = await promise;
      expect(result).not.toBeNull();
      expect(result!.recipients).toContain('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555');
      expect(result!.recipients).toContain('FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000');
      expect(result!.outputMode).toBe('sibling');
    });

    it('returns null when user cancels', async () => {
      const keys = [makePublicKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice')];

      const promise = showRecipientDialog(keys, 'replace');

      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-cancel-btn', 'click');

      const result = await promise;
      expect(result).toBeNull();
    });

    it('returns null when no recipients are checked and user clicks OK', async () => {
      const keys = [
        makePublicKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice'),
        makePublicKey('FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000', 'Bob'),
      ];

      const promise = showRecipientDialog(keys, 'replace');

      // Don't check any recipients, just click OK
      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-ok-btn', 'click');

      const result = await promise;
      expect(result).toBeNull();
    });

    it('auto-checks the only key when a single public key is provided', async () => {
      const keys = [makePublicKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice')];

      const promise = showRecipientDialog(keys, 'sub-block');

      // With a single key, the checkbox is auto-checked in the HTML
      const ui = (globalThis as any).__testUI;
      // The output mode should default to the passed-in value
      ui.fireEvent('cipherblock-ok-btn', 'click');

      const result = await promise;
      expect(result).not.toBeNull();
      expect(result!.recipients).toEqual(['AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555']);
      expect(result!.outputMode).toBe('sub-block');
    });

    it('returns null when user clicks the overlay background', async () => {
      const keys = [makePublicKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice')];

      const promise = showRecipientDialog(keys, 'replace');

      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-recipient-overlay', 'click', {
        target: { id: 'cipherblock-recipient-overlay' },
      });

      const result = await promise;
      expect(result).toBeNull();
    });
  });

  // **Validates: Requirements 8.4, 8.5**
  describe('showKeySelectionDialog', () => {
    it('returns the selected fingerprint when user confirms', async () => {
      const keys = [
        makePrivateKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice <alice@example.com>'),
        makePrivateKey('FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000', 'Bob <bob@example.com>'),
      ];

      const promise = showKeySelectionDialog(keys);

      // First radio is auto-selected by default
      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-ok-btn', 'click');

      const result = await promise;
      expect(result).toBe('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555');
    });

    it('returns null when user cancels', async () => {
      const keys = [makePrivateKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice')];

      const promise = showKeySelectionDialog(keys);

      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-cancel-btn', 'click');

      const result = await promise;
      expect(result).toBeNull();
    });

    it('returns null when user clicks the overlay background', async () => {
      const keys = [makePrivateKey('AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555', 'Alice')];

      const promise = showKeySelectionDialog(keys);

      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-key-overlay', 'click', {
        target: { id: 'cipherblock-key-overlay' },
      });

      const result = await promise;
      expect(result).toBeNull();
    });
  });

  // **Validates: Requirements 4.5, 9.4**
  describe('showPassphrasePrompt', () => {
    it('returns the entered passphrase when user confirms', async () => {
      const promise = showPassphrasePrompt();

      const ui = (globalThis as any).__testUI;
      ui.setPassphraseValue('my-secret-passphrase');
      ui.fireEvent('cipherblock-ok-btn', 'click');

      const result = await promise;
      expect(result).toBe('my-secret-passphrase');
    });

    it('returns empty string when user confirms without entering a passphrase', async () => {
      const promise = showPassphrasePrompt();

      const ui = (globalThis as any).__testUI;
      // Don't set any value, just click OK
      ui.fireEvent('cipherblock-ok-btn', 'click');

      const result = await promise;
      expect(result).toBe('');
    });

    it('rejects when user cancels', async () => {
      const promise = showPassphrasePrompt();

      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-cancel-btn', 'click');

      await expect(promise).rejects.toThrow('Passphrase entry cancelled');
    });

    it('rejects when user clicks the overlay background', async () => {
      const promise = showPassphrasePrompt();

      const ui = (globalThis as any).__testUI;
      ui.fireEvent('cipherblock-passphrase-overlay', 'click', {
        target: { id: 'cipherblock-passphrase-overlay' },
      });

      await expect(promise).rejects.toThrow('Passphrase entry cancelled');
    });
  });
});
