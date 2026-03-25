// CipherBlock – Unit tests for Encryption Service
// Test framework: Vitest
// Source: src/encryption-service.ts
// Validates: Requirements 3.2, 3.4, 11.4, 9.4

import { describe, it, expect, beforeAll } from 'vitest';
import * as openpgp from 'openpgp';
import { EncryptionService } from './encryption-service';
import { OpenPGPAdapter } from './openpgp-adapter';
import { EmptyBlockError, NoKeysError } from './errors';
import type { IKeyStore } from './interfaces';
import type { StoredKey } from './types';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

// --- Fixtures ---

let publicKeyArmored: string;
let fingerprint: string;
let userID: string;

beforeAll(async () => {
  const { publicKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'Test User', email: 'test@example.com' }],
    format: 'armored',
    passphrase: undefined,
  });
  publicKeyArmored = publicKey;

  const parsed = await openpgp.readKey({ armoredKey: publicKey });
  fingerprint = parsed.getFingerprint();
  userID = parsed.users[0]?.userID?.userID ?? 'Test User <test@example.com>';
});

/** Create a mock IKeyStore that returns the pre-generated key for the known fingerprint. */
function createMockKeyStore(): IKeyStore {
  const storedKey: () => StoredKey = () => ({
    fingerprint,
    userID,
    type: 'public' as const,
    creationDate: new Date(),
    armoredKey: publicKeyArmored,
  });

  return {
    importKey: async () => { throw new Error('not implemented'); },
    removeKey: async () => { throw new Error('not implemented'); },
    listKeys: async () => [storedKey()],
    getKey: async (fp: string) => (fp === fingerprint ? storedKey() : null),
    getPublicKeys: async () => [storedKey()],
    getPrivateKeys: async () => [],
  };
}

// --- Tests ---

describe('Encryption Service Unit Tests', () => {
  const adapter = new OpenPGPAdapter();

  describe('encryption with one recipient produces armored output', () => {
    it('should return an armored PGP message and recipientCount of 1', async () => {
      const keyStore = createMockKeyStore();
      const service = new EncryptionService(adapter, keyStore);

      const result = await service.encrypt('Hello, secret world!', [fingerprint]);

      expect(result.armoredMessage.trim()).toMatch(/^-----BEGIN PGP MESSAGE-----/);
      expect(result.armoredMessage.trim()).toMatch(/-----END PGP MESSAGE-----$/);
      expect(result.recipientCount).toBe(1);
    });
  });

  describe('encryption with empty plaintext throws EmptyBlockError', () => {
    it('should throw EmptyBlockError for an empty string', async () => {
      const keyStore = createMockKeyStore();
      const service = new EncryptionService(adapter, keyStore);

      await expect(service.encrypt('', [fingerprint])).rejects.toThrow(EmptyBlockError);
    });

    it('should throw EmptyBlockError for whitespace-only string', async () => {
      const keyStore = createMockKeyStore();
      const service = new EncryptionService(adapter, keyStore);

      await expect(service.encrypt('   \n\t  ', [fingerprint])).rejects.toThrow(EmptyBlockError);
    });
  });

  describe('encryption with no recipients throws NoKeysError', () => {
    it('should throw NoKeysError for an empty recipients array', async () => {
      const keyStore = createMockKeyStore();
      const service = new EncryptionService(adapter, keyStore);

      await expect(service.encrypt('some text', [])).rejects.toThrow(NoKeysError);
    });
  });
});
