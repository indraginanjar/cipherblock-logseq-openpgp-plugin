// CipherBlock – Unit tests for Decryption Service
// Test framework: Vitest
// Source: src/decryption-service.ts
// Validates: Requirements 4.1, 4.3, 4.4, 4.5, 9.4

import { describe, it, expect, beforeAll, vi } from 'vitest';
import * as openpgp from 'openpgp';
import { DecryptionService } from './decryption-service';
import { OpenPGPAdapter } from './openpgp-adapter';
import { InvalidCiphertextError, KeyMismatchError, PassphraseError } from './errors';
import type { IKeyStore } from './interfaces';
import type { StoredKey } from './types';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

// --- Key fixtures ---

interface TestKeyPair {
  fingerprint: string;
  userID: string;
  publicKey: string;
  privateKey: string;
}

async function generateKeyPair(name: string, email: string, passphrase?: string): Promise<TestKeyPair> {
  const { publicKey, privateKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name, email }],
    format: 'armored',
    passphrase: passphrase ?? undefined,
  });
  const parsed = await openpgp.readKey({ armoredKey: publicKey });
  const fingerprint = parsed.getFingerprint();
  const userID = parsed.users[0]?.userID?.userID ?? `${name} <${email}>`;
  return { fingerprint, userID, publicKey, privateKey };
}

// Unprotected key pair for basic encrypt/decrypt
let normalKeyPair: TestKeyPair;
// Second key pair for wrong-key tests
let wrongKeyPair: TestKeyPair;
// Passphrase-protected key pair
let protectedKeyPair: TestKeyPair;
const PASSPHRASE = 'unit-test-passphrase-42';

beforeAll(async () => {
  [normalKeyPair, wrongKeyPair, protectedKeyPair] = await Promise.all([
    generateKeyPair('Normal', 'normal@test.com'),
    generateKeyPair('Wrong', 'wrong@test.com'),
    generateKeyPair('Protected', 'protected@test.com', PASSPHRASE),
  ]);
}, 120_000);

// --- Helpers ---

function createKeyStore(privateKeys: TestKeyPair[]): IKeyStore {
  const stored: StoredKey[] = privateKeys.map((k) => ({
    fingerprint: k.fingerprint,
    userID: k.userID,
    type: 'private' as const,
    creationDate: new Date(),
    armoredKey: k.privateKey,
  }));

  return {
    importKey: async () => { throw new Error('not implemented'); },
    removeKey: async () => { throw new Error('not implemented'); },
    listKeys: async () => stored,
    getKey: async (fp: string) => stored.find((k) => k.fingerprint === fp) ?? null,
    getPublicKeys: async () => [],
    getPrivateKeys: async () => stored,
  };
}

// --- Tests ---

describe('Decryption Service Unit Tests', () => {
  const adapter = new OpenPGPAdapter();

  describe('decryption of a known armored message with correct key', () => {
    it('should decrypt and return the original plaintext', async () => {
      const plaintext = 'Hello, secret world!';
      const armoredMessage = await adapter.encrypt(plaintext, [normalKeyPair.publicKey]);

      const keyStore = createKeyStore([normalKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      const result = await service.decrypt(armoredMessage, normalKeyPair.fingerprint);

      expect(result.plaintext).toBe(plaintext);
    });
  });

  describe('decryption with wrong key throws KeyMismatchError', () => {
    it('should throw KeyMismatchError when private key is not a recipient', async () => {
      // Encrypt for normalKeyPair only
      const armoredMessage = await adapter.encrypt('secret data', [normalKeyPair.publicKey]);

      // Attempt to decrypt with wrongKeyPair
      const keyStore = createKeyStore([wrongKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      await expect(
        service.decrypt(armoredMessage, wrongKeyPair.fingerprint),
      ).rejects.toThrow(KeyMismatchError);
    });
  });

  describe('decryption of non-PGP content throws InvalidCiphertextError', () => {
    it('should throw InvalidCiphertextError for plain text', async () => {
      const keyStore = createKeyStore([normalKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      await expect(
        service.decrypt('This is not encrypted at all', normalKeyPair.fingerprint),
      ).rejects.toThrow(InvalidCiphertextError);
    });

    it('should throw InvalidCiphertextError for empty string', async () => {
      const keyStore = createKeyStore([normalKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      await expect(
        service.decrypt('', normalKeyPair.fingerprint),
      ).rejects.toThrow(InvalidCiphertextError);
    });
  });

  describe('passphrase prompt is called for protected keys', () => {
    it('should invoke passphraseProvider and decrypt successfully', async () => {
      const plaintext = 'Protected secret';
      const armoredMessage = await adapter.encrypt(plaintext, [protectedKeyPair.publicKey]);

      const keyStore = createKeyStore([protectedKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      const passphraseProvider = vi.fn().mockResolvedValue(PASSPHRASE);

      const result = await service.decrypt(
        armoredMessage,
        protectedKeyPair.fingerprint,
        passphraseProvider,
      );

      expect(passphraseProvider).toHaveBeenCalled();
      expect(result.plaintext).toBe(plaintext);
    });

    it('should throw PassphraseError when no passphraseProvider is given for a protected key', async () => {
      const armoredMessage = await adapter.encrypt('secret', [protectedKeyPair.publicKey]);

      const keyStore = createKeyStore([protectedKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      await expect(
        service.decrypt(armoredMessage, protectedKeyPair.fingerprint),
      ).rejects.toThrow(PassphraseError);
    });
  });

  describe('passphrase retry logic (up to 3 attempts)', () => {
    it('should succeed on the second attempt after one wrong passphrase', async () => {
      const plaintext = 'Retry secret';
      const armoredMessage = await adapter.encrypt(plaintext, [protectedKeyPair.publicKey]);

      const keyStore = createKeyStore([protectedKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      const passphraseProvider = vi.fn()
        .mockResolvedValueOnce('wrong-passphrase')
        .mockResolvedValueOnce(PASSPHRASE);

      const result = await service.decrypt(
        armoredMessage,
        protectedKeyPair.fingerprint,
        passphraseProvider,
      );

      expect(passphraseProvider).toHaveBeenCalledTimes(2);
      expect(result.plaintext).toBe(plaintext);
    });

    it('should throw PassphraseError after 3 wrong passphrase attempts', async () => {
      const armoredMessage = await adapter.encrypt('secret', [protectedKeyPair.publicKey]);

      const keyStore = createKeyStore([protectedKeyPair]);
      const service = new DecryptionService(adapter, keyStore);

      const passphraseProvider = vi.fn()
        .mockResolvedValueOnce('wrong1')
        .mockResolvedValueOnce('wrong2')
        .mockResolvedValueOnce('wrong3');

      await expect(
        service.decrypt(armoredMessage, protectedKeyPair.fingerprint, passphraseProvider),
      ).rejects.toThrow(PassphraseError);

      expect(passphraseProvider).toHaveBeenCalledTimes(3);
    });
  });
});
