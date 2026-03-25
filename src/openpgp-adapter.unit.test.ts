// CipherBlock – Unit tests for OpenPGP Adapter
// Test framework: Vitest
// Source: src/openpgp-adapter.ts
// Validates: Requirements 6.1, 6.2, 6.3, 6.4, 9.4

import { describe, it, expect, beforeAll } from 'vitest';
import * as openpgp from 'openpgp';
import { OpenPGPAdapter } from './openpgp-adapter';
import { KeyImportError } from './errors';

// Make openpgp available globally so the adapter's lazy-loader finds it
beforeAll(() => {
  (globalThis as any).openpgp = openpgp;
});

const adapter = new OpenPGPAdapter();

// --- Fixtures generated once for all tests ---

let publicKeyArmored: string;
let privateKeyArmored: string;
let keyFingerprint: string;

beforeAll(async () => {
  const { publicKey, privateKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'Alice Test', email: 'alice@example.com' }],
    format: 'armored',
    passphrase: undefined,
  });
  publicKeyArmored = publicKey;
  privateKeyArmored = privateKey;

  // Extract fingerprint for later assertions
  const parsed = await openpgp.readKey({ armoredKey: publicKey });
  keyFingerprint = parsed.getFingerprint();
});

// --- Tests ---

describe('OpenPGP Adapter Unit Tests', () => {
  describe('parseKey – valid public key', () => {
    it('should parse a valid armored public key and return correct metadata', async () => {
      const result = await adapter.parseKey(publicKeyArmored);

      expect(result.fingerprint).toBe(keyFingerprint);
      expect(result.userID).toContain('Alice Test');
      expect(result.userID).toContain('alice@example.com');
      expect(result.type).toBe('public');
      expect(result.creationDate).toBeInstanceOf(Date);
      expect(result.creationDate.getTime()).not.toBeNaN();
      expect(result.armoredKey).toBe(publicKeyArmored.trim());
    });
  });

  describe('parseKey – valid private key', () => {
    it('should parse a valid armored private key and return correct metadata', async () => {
      const result = await adapter.parseKey(privateKeyArmored);

      expect(result.fingerprint).toBe(keyFingerprint);
      expect(result.userID).toContain('Alice Test');
      expect(result.userID).toContain('alice@example.com');
      expect(result.type).toBe('private');
      expect(result.creationDate).toBeInstanceOf(Date);
      expect(result.creationDate.getTime()).not.toBeNaN();
      expect(result.armoredKey).toBe(privateKeyArmored.trim());
    });
  });

  describe('parseKey – invalid/malformed input', () => {
    it('should throw KeyImportError for an empty string', async () => {
      await expect(adapter.parseKey('')).rejects.toThrow(KeyImportError);
    });

    it('should throw KeyImportError for random text', async () => {
      await expect(adapter.parseKey('not a key at all')).rejects.toThrow(KeyImportError);
    });

    it('should throw KeyImportError for a truncated/malformed armored block', async () => {
      const malformed =
        '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\ngarbage data here\n-----END PGP PUBLIC KEY BLOCK-----';
      await expect(adapter.parseKey(malformed)).rejects.toThrow(KeyImportError);
    });

    it('should throw KeyImportError when input is not a string', async () => {
      // @ts-expect-error testing runtime guard
      await expect(adapter.parseKey(null)).rejects.toThrow(KeyImportError);
      // @ts-expect-error testing runtime guard
      await expect(adapter.parseKey(undefined)).rejects.toThrow(KeyImportError);
      // @ts-expect-error testing runtime guard
      await expect(adapter.parseKey(42)).rejects.toThrow(KeyImportError);
    });
  });

  describe('encrypt and decrypt – single recipient round-trip', () => {
    it('should encrypt plaintext and decrypt back to the original', async () => {
      const plaintext = 'Hello, this is a secret message!';

      const armored = await adapter.encrypt(plaintext, [publicKeyArmored]);

      // Verify armored format (Req 6.1)
      expect(armored.trim()).toMatch(/^-----BEGIN PGP MESSAGE-----/);
      expect(armored.trim()).toMatch(/-----END PGP MESSAGE-----$/);

      // Decrypt and verify round-trip
      const decrypted = await adapter.decrypt(armored, privateKeyArmored);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle multi-line plaintext correctly', async () => {
      const plaintext = 'Line 1\nLine 2\nLine 3\n\nLine 5 after blank';

      const armored = await adapter.encrypt(plaintext, [publicKeyArmored]);
      const decrypted = await adapter.decrypt(armored, privateKeyArmored);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle unicode plaintext correctly', async () => {
      const plaintext = '日本語テスト 🔐 émojis & spëcial chars';

      const armored = await adapter.encrypt(plaintext, [publicKeyArmored]);
      const decrypted = await adapter.decrypt(armored, privateKeyArmored);

      expect(decrypted).toBe(plaintext);
    });
  });
});
