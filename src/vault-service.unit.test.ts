// CipherBlock – Unit tests for Vault Service
// Test framework: Vitest
// Source: src/vault-service.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { VaultService } from './vault-service';
import { EmptyBlockError } from './errors';
import type {
  IEncryptionService,
  ISettingsManager,
  IMetadataWriter,
  IKeyStore,
} from './interfaces';
import type { PluginSettings, MetadataMode, EncryptionMetadata } from './types';

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

// --- Unit Tests ---

describe('Vault Service Unit Tests', () => {
  const blockUuid = 'test-block-uuid';
  const plaintext = 'Secret vault content';
  const fingerprints = ['AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555'];

  // **Validates: Requirements 12.1, 12.2, 12.3, 12.4**
  describe('vault page creation with valid input', () => {
    it('creates a vault page, inserts encrypted sub-block, and replaces original block', async () => {
      const encService = createMockEncryptionService();
      const settingsManager = createMockSettingsManager({ metadataEnabled: false });
      const metadataWriter = createMockMetadataWriter();
      const keyStore = createMockKeyStore(fingerprints);

      const vaultService = new VaultService(encService, settingsManager, metadataWriter, keyStore);
      const result = await vaultService.encryptToVault(blockUuid, plaintext, fingerprints);

      // 12.1: Vault page name matches Vault-[hex]
      expect(result.vaultPageName).toMatch(/^Vault-[0-9a-f]{8,}$/);

      // Page was created
      expect(createPageMock).toHaveBeenCalledWith(result.vaultPageName);

      // 12.2: First block updated with title
      expect(updateBlockMock).toHaveBeenCalledWith(
        'first-block-uuid',
        expect.stringContaining('[[Vault]]'),
      );

      // 12.3: Sub-block contains armored PGP message
      expect(insertBlockMock).toHaveBeenCalledWith(
        'first-block-uuid',
        expect.stringContaining('-----BEGIN PGP MESSAGE-----'),
        { sibling: false },
      );

      // 12.4: Original block replaced with vault link
      expect(updateBlockMock).toHaveBeenCalledWith(blockUuid, `[[${result.vaultPageName}]]`);
      expect(result.vaultLink).toBe(`[[${result.vaultPageName}]]`);
    });
  });

  // **Validates: Requirements 12.6**
  describe('empty block rejection', () => {
    it('throws EmptyBlockError for empty string', async () => {
      const vaultService = new VaultService(
        createMockEncryptionService(),
        createMockSettingsManager(),
        createMockMetadataWriter(),
        createMockKeyStore([]),
      );

      await expect(
        vaultService.encryptToVault(blockUuid, '', fingerprints),
      ).rejects.toThrow(EmptyBlockError);
    });

    it('throws EmptyBlockError for whitespace-only string', async () => {
      const vaultService = new VaultService(
        createMockEncryptionService(),
        createMockSettingsManager(),
        createMockMetadataWriter(),
        createMockKeyStore([]),
      );

      await expect(
        vaultService.encryptToVault(blockUuid, '   \n\t  ', fingerprints),
      ).rejects.toThrow(EmptyBlockError);
    });
  });

  // **Validates: Requirements 12.7**
  describe('generateHex', () => {
    it('produces a hex string of at least 8 characters', () => {
      const vaultService = new VaultService(
        createMockEncryptionService(),
        createMockSettingsManager(),
        createMockMetadataWriter(),
        createMockKeyStore([]),
      );

      const hex = vaultService.generateHex(8);
      expect(hex.length).toBeGreaterThanOrEqual(8);
      expect(hex).toMatch(/^[0-9a-f]+$/);
    });

    it('produces only hex characters for various lengths', () => {
      const vaultService = new VaultService(
        createMockEncryptionService(),
        createMockSettingsManager(),
        createMockMetadataWriter(),
        createMockKeyStore([]),
      );

      for (const len of [8, 16, 32]) {
        const hex = vaultService.generateHex(len);
        expect(hex.length).toBeGreaterThanOrEqual(8);
        expect(hex).toMatch(/^[0-9a-f]+$/);
      }
    });
  });

  // **Validates: Requirements 14.7**
  describe('vault encryption metadata handling', () => {
    it('writes metadata when metadataEnabled is true', async () => {
      const encService = createMockEncryptionService();
      const metadataWriter = createMockMetadataWriter();
      const settingsManager = createMockSettingsManager({
        metadataEnabled: true,
        metadataMode: 'attributes',
      });
      const keyStore = createMockKeyStore(fingerprints);

      const vaultService = new VaultService(encService, settingsManager, metadataWriter, keyStore);
      await vaultService.encryptToVault(blockUuid, plaintext, fingerprints);

      expect(metadataWriter.writeMetadata).toHaveBeenCalledOnce();

      const [calledBlockUuid, calledMetadata, calledMode] =
        metadataWriter.writeMetadata.mock.calls[0] as [string, EncryptionMetadata, MetadataMode];

      expect(calledBlockUuid).toBe('inserted-block-uuid');
      expect(calledMode).toBe('attributes');
      expect(calledMetadata.recipientFingerprints).toEqual(fingerprints);
      expect(calledMetadata.recipientCount).toBe(fingerprints.length);
      expect(calledMetadata.encryptedAt).toBeTruthy();
      expect(new Date(calledMetadata.encryptedAt).toISOString()).toBe(calledMetadata.encryptedAt);
    });

    it('skips metadata when metadataEnabled is false', async () => {
      const encService = createMockEncryptionService();
      const metadataWriter = createMockMetadataWriter();
      const settingsManager = createMockSettingsManager({
        metadataEnabled: false,
      });
      const keyStore = createMockKeyStore(fingerprints);

      const vaultService = new VaultService(encService, settingsManager, metadataWriter, keyStore);
      await vaultService.encryptToVault(blockUuid, plaintext, fingerprints);

      expect(metadataWriter.writeMetadata).not.toHaveBeenCalled();
    });
  });
});
