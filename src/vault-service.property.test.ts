// CipherBlock – Property-based tests for Vault Service
// Test framework: Vitest with fast-check
// Source: src/vault-service.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fc from 'fast-check';
import { VaultService } from './vault-service';
import type {
  IEncryptionService,
  ISettingsManager,
  IMetadataWriter,
  IKeyStore,
} from './interfaces';
import type { EncryptionMetadata, MetadataMode, PluginSettings } from './types';

// --- Logseq API mock setup ---

let createPageMock: ReturnType<typeof vi.fn>;
let getPageBlocksTreeMock: ReturnType<typeof vi.fn>;
let insertBlockMock: ReturnType<typeof vi.fn>;
let updateBlockMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  createPageMock = vi.fn(async () => ({ name: 'mock-page' }));
  getPageBlocksTreeMock = vi.fn(async () => [{ uuid: 'first-block-uuid' }]);
  insertBlockMock = vi.fn(async () => ({ uuid: 'inserted-block-uuid' }));
  updateBlockMock = vi.fn(async () => undefined);

  (globalThis as any).logseq = {
    Editor: {
      createPage: createPageMock,
      getPageBlocksTree: getPageBlocksTreeMock,
      insertBlock: insertBlockMock,
      updateBlock: updateBlockMock,
    },
  };

  // Provide crypto.getRandomValues for hex generation
  if (typeof globalThis.crypto === 'undefined') {
    (globalThis as any).crypto = {
      getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) {
          arr[i] = Math.floor(Math.random() * 256);
        }
        return arr;
      },
    };
  }
});

// --- Arbitraries ---

const fingerprintArb = fc.hexaString({ minLength: 40, maxLength: 40 });

const blockUuidArb = fc.uuid();

/** Non-empty plaintext that won't be whitespace-only. */
const plaintextArb = fc
  .string({ minLength: 1, maxLength: 200 })
  .filter((s) => s.trim().length > 0);

/** 1..5 recipient fingerprints. */
const recipientFingerprintsArb = fc.array(fingerprintArb, { minLength: 1, maxLength: 5 });

const metadataModeArb: fc.Arbitrary<MetadataMode> = fc.constantFrom('attributes', 'sub-blocks');

// --- Helper factories ---

function createMockEncryptionService(): IEncryptionService {
  return {
    encrypt: vi.fn(async (_plaintext: string, recipientFingerprints: string[]) => ({
      armoredMessage:
        '-----BEGIN PGP MESSAGE-----\nrandomciphertext\n-----END PGP MESSAGE-----',
      recipientCount: recipientFingerprints.length,
    })),
  };
}

function createMockSettingsManager(
  overrides: Partial<PluginSettings> = {},
): ISettingsManager {
  const settings: PluginSettings = {
    defaultKeyFingerprint: null,
    outputMode: 'replace',
    passphraseCachingEnabled: false,
    metadataEnabled: false,
    metadataMode: 'attributes',
    ...overrides,
  };
  return {
    getSettings: vi.fn(() => settings),
    onSettingsChanged: vi.fn(),
  };
}

function createMockMetadataWriter(): IMetadataWriter & { writeMetadata: ReturnType<typeof vi.fn> } {
  return {
    writeMetadata: vi.fn(async () => undefined),
  };
}

function createMockKeyStore(fingerprints: string[]): IKeyStore {
  return {
    importKey: vi.fn(),
    removeKey: vi.fn(),
    listKeys: vi.fn(async () => []),
    getKey: vi.fn(async (fp: string) => {
      if (fingerprints.includes(fp)) {
        return {
          fingerprint: fp,
          userID: `User <${fp.slice(0, 8)}@test.com>`,
          type: 'public' as const,
          creationDate: new Date(),
          armoredKey: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nmock\n-----END PGP PUBLIC KEY BLOCK-----',
        };
      }
      return null;
    }),
    getPublicKeys: vi.fn(async () => []),
    getPrivateKeys: vi.fn(async () => []),
  };
}

// --- Property Tests ---

describe('Vault Service Property Tests', () => {
  // Feature: logseq-cipherblock, Property 18: Vault page structure invariants
  // **Validates: Requirements 12.1, 12.2, 12.3, 12.4**
  describe('Property 18: Vault page structure invariants', () => {
    it('vault page name matches Vault-[0-9a-f]{8,}, first block updated to title, sub-block contains armored message, original block replaced with vault link', async () => {
      await fc.assert(
        fc.asyncProperty(
          blockUuidArb,
          plaintextArb,
          recipientFingerprintsArb,
          async (blockUuid, plaintext, recipientFingerprints) => {
            // Reset mocks
            createPageMock.mockClear();
            getPageBlocksTreeMock.mockClear();
            insertBlockMock.mockClear();
            updateBlockMock.mockClear();

            const encService = createMockEncryptionService();
            const settingsManager = createMockSettingsManager({ metadataEnabled: false });
            const metadataWriter = createMockMetadataWriter();
            const keyStore = createMockKeyStore(recipientFingerprints);

            const vaultService = new VaultService(
              encService,
              settingsManager,
              metadataWriter,
              keyStore,
            );

            const result = await vaultService.encryptToVault(
              blockUuid,
              plaintext,
              recipientFingerprints,
            );

            // 12.1: Vault page name matches Vault-[0-9a-f]{8,}
            expect(result.vaultPageName).toMatch(/^Vault-[0-9a-f]{8,}$/);

            // createPage was called with the vault page name
            expect(createPageMock).toHaveBeenCalledWith(result.vaultPageName);

            // 12.2: First block text is updated (contains the vault page hex)
            // The implementation sets first block to `[[Vault]]-<hex>`
            expect(updateBlockMock).toHaveBeenCalled();
            const firstBlockUpdateCall = updateBlockMock.mock.calls.find(
              (call: any[]) => call[0] === 'first-block-uuid',
            );
            expect(firstBlockUpdateCall).toBeDefined();

            // 12.3: Sub-block contains valid armored PGP message
            expect(insertBlockMock).toHaveBeenCalledWith(
              'first-block-uuid',
              expect.stringContaining('-----BEGIN PGP MESSAGE-----'),
              { sibling: false },
            );
            const insertedContent: string = insertBlockMock.mock.calls[0][1];
            expect(insertedContent).toContain('-----END PGP MESSAGE-----');

            // 12.4: Original block replaced with vault link
            const originalBlockUpdateCall = updateBlockMock.mock.calls.find(
              (call: any[]) => call[0] === blockUuid,
            );
            expect(originalBlockUpdateCall).toBeDefined();
            expect(originalBlockUpdateCall![1]).toBe(`[[${result.vaultPageName}]]`);
            expect(result.vaultLink).toBe(`[[${result.vaultPageName}]]`);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 19: Random hex generator output
  // **Validates: Requirements 12.7**
  describe('Property 19: Random hex generator output', () => {
    it('output is at least 8 hex characters matching [0-9a-f]{8,}', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 8, max: 64 }),
          async (length) => {
            const encService = createMockEncryptionService();
            const settingsManager = createMockSettingsManager();
            const metadataWriter = createMockMetadataWriter();
            const keyStore = createMockKeyStore([]);

            const vaultService = new VaultService(
              encService,
              settingsManager,
              metadataWriter,
              keyStore,
            );

            const hex = vaultService.generateHex(length);

            // Output must be at least 8 hex characters
            expect(hex.length).toBeGreaterThanOrEqual(8);

            // Output must consist only of hex characters
            expect(hex).toMatch(/^[0-9a-f]+$/);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 22: Vault encryption includes metadata
  // **Validates: Requirements 14.7**
  describe('Property 22: Vault encryption includes metadata', () => {
    it('when metadata is enabled, the vault ciphertext block has metadata written using the configured mode with all required fields', async () => {
      await fc.assert(
        fc.asyncProperty(
          blockUuidArb,
          plaintextArb,
          recipientFingerprintsArb,
          metadataModeArb,
          async (blockUuid, plaintext, recipientFingerprints, metadataMode) => {
            // Reset mocks
            createPageMock.mockClear();
            getPageBlocksTreeMock.mockClear();
            insertBlockMock.mockClear();
            updateBlockMock.mockClear();

            const encService = createMockEncryptionService();
            const settingsManager = createMockSettingsManager({
              metadataEnabled: true,
              metadataMode: metadataMode,
            });
            const metadataWriter = createMockMetadataWriter();
            const keyStore = createMockKeyStore(recipientFingerprints);

            const vaultService = new VaultService(
              encService,
              settingsManager,
              metadataWriter,
              keyStore,
            );

            await vaultService.encryptToVault(blockUuid, plaintext, recipientFingerprints);

            // Metadata writer must have been called
            expect(metadataWriter.writeMetadata).toHaveBeenCalledOnce();

            const [calledBlockUuid, calledMetadata, calledMode] =
              metadataWriter.writeMetadata.mock.calls[0] as [string, EncryptionMetadata, MetadataMode];

            // Called on the inserted ciphertext block
            expect(calledBlockUuid).toBe('inserted-block-uuid');

            // Mode matches the configured metadata mode
            expect(calledMode).toBe(metadataMode);

            // All required metadata fields are present
            expect(calledMetadata.recipientFingerprints).toEqual(recipientFingerprints);
            expect(calledMetadata.recipientFingerprints.length).toBe(
              calledMetadata.recipientCount,
            );
            expect(calledMetadata.recipientUserIDs).toHaveLength(recipientFingerprints.length);
            expect(calledMetadata.encryptedAt).toBeTruthy();
            // encryptedAt should be valid ISO 8601
            const parsedDate = new Date(calledMetadata.encryptedAt);
            expect(parsedDate.toISOString()).toBe(calledMetadata.encryptedAt);
            expect(calledMetadata.keyAlgorithm).toBeTruthy();
            expect(calledMetadata.recipientCount).toBe(recipientFingerprints.length);
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
