// CipherBlock – Property-based tests for Settings Module
// Test framework: Vitest with fast-check
// Source: src/settings-manager.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fc from 'fast-check';
import { SettingsManager, settingsSchema } from './settings-manager';
import type { IKeyStore } from './interfaces';
import type { StoredKey, OutputMode, MetadataMode } from './types';

// --- Logseq API mock setup ---

let mockSettings: Record<string, unknown> = {};
let settingsChangedCallbacks: Array<(newSettings: Record<string, unknown>) => void> = [];

beforeEach(() => {
  mockSettings = {};
  settingsChangedCallbacks = [];

  (globalThis as any).logseq = {
    useSettingsSchema: vi.fn(),
    get settings() {
      return mockSettings;
    },
    set settings(val: Record<string, unknown>) {
      mockSettings = val;
    },
    onSettingsChanged: vi.fn((cb: (newSettings: Record<string, unknown>) => void) => {
      settingsChangedCallbacks.push(cb);
    }),
    updateSettings: vi.fn((newSettings: Record<string, unknown>) => {
      mockSettings = { ...mockSettings, ...newSettings };
      for (const cb of settingsChangedCallbacks) {
        cb(mockSettings);
      }
    }),
  };
});

// --- Mock KeyStore factory ---

function createMockKeyStore(privateKeys: StoredKey[] = []): IKeyStore {
  return {
    importKey: vi.fn(),
    removeKey: vi.fn(),
    listKeys: vi.fn(async () => privateKeys),
    getKey: vi.fn(),
    getPublicKeys: vi.fn(async () => []),
    getPrivateKeys: vi.fn(async () => privateKeys),
  };
}

// --- Arbitraries ---

/** Arbitrary for a hex fingerprint string. */
const fingerprintArb = fc.hexaString({ minLength: 40, maxLength: 40 }).map((s) => s.toLowerCase());

/** Arbitrary for a user ID string. */
const userIdArb = fc.tuple(fc.string({ minLength: 1, maxLength: 20 }), fc.emailAddress()).map(
  ([name, email]) => `${name} <${email}>`,
);

/** Arbitrary that generates a single StoredKey of type 'private'. */
const privateKeyArb = fc.tuple(fingerprintArb, userIdArb).map(
  ([fingerprint, userID]): StoredKey => ({
    fingerprint,
    userID,
    type: 'private',
    creationDate: new Date(),
    armoredKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake-${fingerprint}\n-----END PGP PRIVATE KEY BLOCK-----`,
  }),
);

/** Arbitrary for OutputMode values. */
const outputModeArb = fc.constantFrom<OutputMode>('replace', 'sibling', 'sub-block', 'clipboard');

/** Arbitrary for MetadataMode values. */
const metadataModeArb = fc.constantFrom<MetadataMode>('attributes', 'sub-blocks');

/** Arbitrary for boolean values. */
const boolArb = fc.boolean();

// --- Property Tests ---

describe('Settings Module Property Tests', () => {
  // Feature: logseq-cipherblock, Property 6: Single private key auto-selects as default
  // Validates: Requirements 2.2
  describe('Property 6: Single private key auto-selects as default', () => {
    it('when only one private key exists, it is automatically the default', async () => {
      await fc.assert(
        fc.asyncProperty(privateKeyArb, async (privateKey) => {
          const keyStore = createMockKeyStore([privateKey]);
          const manager = new SettingsManager(keyStore);

          // Ensure no default key is configured in settings
          mockSettings = { defaultKeyFingerprint: '' };

          const settings = await manager.getSettingsWithAutoDefault();

          // The single private key should be auto-selected as default
          expect(settings.defaultKeyFingerprint).toBe(privateKey.fingerprint);
        }),
        { numRuns: 100 },
      );
    });

    it('when multiple private keys exist, no auto-selection occurs', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(privateKeyArb, { minLength: 2, maxLength: 5 }),
          async (privateKeys) => {
            // Ensure unique fingerprints
            const seen = new Set<string>();
            const uniqueKeys = privateKeys.filter((k) => {
              if (seen.has(k.fingerprint)) return false;
              seen.add(k.fingerprint);
              return true;
            });
            if (uniqueKeys.length < 2) return; // skip if deduplication reduced below 2

            const keyStore = createMockKeyStore(uniqueKeys);
            const manager = new SettingsManager(keyStore);

            // No default key configured
            mockSettings = { defaultKeyFingerprint: '' };

            const settings = await manager.getSettingsWithAutoDefault();

            // Should remain null when multiple keys exist
            expect(settings.defaultKeyFingerprint).toBeNull();
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 15: Settings changes apply immediately
  // Validates: Requirements 7.5, 14.8
  describe('Property 15: Settings changes apply immediately', () => {
    it('writing a setting then reading it returns the new value', async () => {
      await fc.assert(
        fc.asyncProperty(
          outputModeArb,
          boolArb,
          boolArb,
          metadataModeArb,
          fingerprintArb,
          async (outputMode, passphraseCaching, metadataEnabled, metadataMode, fingerprint) => {
            const keyStore = createMockKeyStore();
            const manager = new SettingsManager(keyStore);

            // Set initial settings to defaults
            mockSettings = {
              defaultKeyFingerprint: '',
              outputMode: 'replace',
              passphraseCachingEnabled: false,
              metadataEnabled: false,
              metadataMode: 'attributes',
            };

            // Apply new settings (simulating user changing settings in the UI)
            mockSettings = {
              defaultKeyFingerprint: fingerprint,
              outputMode,
              passphraseCachingEnabled: passphraseCaching,
              metadataEnabled,
              metadataMode,
            };

            // Read settings immediately — should reflect the new values
            const settings = manager.getSettings();

            expect(settings.outputMode).toBe(outputMode);
            expect(settings.passphraseCachingEnabled).toBe(passphraseCaching);
            expect(settings.metadataEnabled).toBe(metadataEnabled);
            expect(settings.metadataMode).toBe(metadataMode);
            expect(settings.defaultKeyFingerprint).toBe(fingerprint);
          },
        ),
        { numRuns: 100 },
      );
    });

    it('onSettingsChanged callback fires with updated values including metadataEnabled and metadataMode', async () => {
      await fc.assert(
        fc.asyncProperty(
          outputModeArb,
          boolArb,
          metadataModeArb,
          async (outputMode, metadataEnabled, metadataMode) => {
            const keyStore = createMockKeyStore();
            const manager = new SettingsManager(keyStore);

            // Start with defaults
            mockSettings = {
              defaultKeyFingerprint: '',
              outputMode: 'replace',
              passphraseCachingEnabled: false,
              metadataEnabled: false,
              metadataMode: 'attributes',
            };

            // Register the change listener
            let receivedSettings: any = null;
            manager.onSettingsChanged((s) => {
              receivedSettings = s;
            });

            // Simulate a settings change via the Logseq API
            const newSettings = {
              defaultKeyFingerprint: '',
              outputMode,
              passphraseCachingEnabled: false,
              metadataEnabled,
              metadataMode,
            };
            (globalThis as any).logseq.updateSettings(newSettings);

            // The callback should have fired with the new values
            expect(receivedSettings).not.toBeNull();
            expect(receivedSettings.outputMode).toBe(outputMode);
            expect(receivedSettings.metadataEnabled).toBe(metadataEnabled);
            expect(receivedSettings.metadataMode).toBe(metadataMode);
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
