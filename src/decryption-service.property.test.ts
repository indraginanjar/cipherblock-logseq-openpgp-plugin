// CipherBlock – Property-based tests for Decryption Service
// Test framework: Vitest with fast-check
// Source: src/decryption-service.ts

import { describe, it, expect, beforeAll, vi } from 'vitest';
import * as fc from 'fast-check';
import * as openpgp from 'openpgp';
import { DecryptionService } from './decryption-service';
import { OpenPGPAdapter } from './openpgp-adapter';
import { InvalidCiphertextError, KeyMismatchError } from './errors';
import type { IKeyStore } from './interfaces';
import type { StoredKey } from './types';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

// --- Helpers ---

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

/** Create an in-memory IKeyStore that returns the given private keys. */
function createKeyStore(privateKeys: { fingerprint: string; userID: string; armoredKey: string }[]): IKeyStore {
  const stored: StoredKey[] = privateKeys.map((k) => ({
    fingerprint: k.fingerprint,
    userID: k.userID,
    type: 'private' as const,
    creationDate: new Date(),
    armoredKey: k.armoredKey,
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

// Pre-generated key pairs for Property 12 and 13
let keyPairA: TestKeyPair;
let keyPairB: TestKeyPair;
let protectedKeyPair: TestKeyPair;
const PASSPHRASE = 'test-passphrase-123';

beforeAll(async () => {
  [keyPairA, keyPairB, protectedKeyPair] = await Promise.all([
    generateKeyPair('Alice', 'alice@test.com'),
    generateKeyPair('Bob', 'bob@test.com'),
    generateKeyPair('Charlie', 'charlie@test.com', PASSPHRASE),
  ]);
}, 120_000);

// --- Property Tests ---

describe('Decryption Service Property Tests', () => {
  const adapter = new OpenPGPAdapter();

  // Feature: logseq-cipherblock, Property 11: Invalid armored message detection
  // Validates: Requirements 4.3
  describe('Property 11: Invalid armored message detection', () => {
    it('non-PGP strings cause decryption to fail with InvalidCiphertextError', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 0, maxLength: 500 }).filter(
            (s) => !s.includes('-----BEGIN PGP MESSAGE-----'),
          ),
          async (randomString) => {
            const keyStore = createKeyStore([
              { fingerprint: keyPairA.fingerprint, userID: keyPairA.userID, armoredKey: keyPairA.privateKey },
            ]);
            const service = new DecryptionService(adapter, keyStore);

            await expect(
              service.decrypt(randomString, keyPairA.fingerprint),
            ).rejects.toThrow(InvalidCiphertextError);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 12: Wrong key decryption error
  // Validates: Requirements 4.4
  describe('Property 12: Wrong key decryption error', () => {
    it('decrypting with a non-recipient key fails with KeyMismatchError', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 200 }).filter((s) => s.trim().length > 0),
          async (plaintext) => {
            // Encrypt with key pair A's public key
            const armoredMessage = await adapter.encrypt(plaintext, [keyPairA.publicKey]);

            // Try to decrypt with key pair B (not a recipient)
            const keyStore = createKeyStore([
              { fingerprint: keyPairB.fingerprint, userID: keyPairB.userID, armoredKey: keyPairB.privateKey },
            ]);
            const service = new DecryptionService(adapter, keyStore);

            await expect(
              service.decrypt(armoredMessage, keyPairB.fingerprint),
            ).rejects.toThrow(KeyMismatchError);
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 13: Passphrase-protected key triggers prompt
  // Validates: Requirements 4.5
  describe('Property 13: Passphrase-protected key triggers prompt', () => {
    it('decrypting with a protected key invokes the passphraseProvider', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.string({ minLength: 1, maxLength: 200 }).filter((s) => s.trim().length > 0),
          async (plaintext) => {
            // Encrypt with the protected key pair's public key
            const armoredMessage = await adapter.encrypt(plaintext, [protectedKeyPair.publicKey]);

            const keyStore = createKeyStore([
              { fingerprint: protectedKeyPair.fingerprint, userID: protectedKeyPair.userID, armoredKey: protectedKeyPair.privateKey },
            ]);
            const service = new DecryptionService(adapter, keyStore);

            const passphraseProvider = vi.fn().mockResolvedValue(PASSPHRASE);

            const result = await service.decrypt(
              armoredMessage,
              protectedKeyPair.fingerprint,
              passphraseProvider,
            );

            // The passphrase provider should have been called
            expect(passphraseProvider).toHaveBeenCalled();
            // And decryption should succeed with the correct plaintext
            expect(result.plaintext).toBe(plaintext);
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
