// CipherBlock – Unit tests for Metadata Writer
// Test framework: Vitest
// Source: src/metadata-writer.ts
// Requirements: 14.4, 14.5, 14.6, 9.4

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MetadataWriter } from './metadata-writer';
import type { EncryptionMetadata } from './types';

// --- Logseq API mock setup (same pattern as property test file) ---

let updateBlockMock: ReturnType<typeof vi.fn>;
let insertBlockMock: ReturnType<typeof vi.fn>;
let getBlockMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  updateBlockMock = vi.fn(async () => undefined);
  insertBlockMock = vi.fn(async () => ({ uuid: 'child-block-uuid' }));
  getBlockMock = vi.fn(async (uuid: string) => ({
    uuid,
    content: '-----BEGIN PGP MESSAGE-----\nsome ciphertext\n-----END PGP MESSAGE-----',
  }));

  (globalThis as any).logseq = {
    Editor: {
      updateBlock: updateBlockMock,
      insertBlock: insertBlockMock,
      getBlock: getBlockMock,
    },
  };
});

// --- Helpers ---

function makeSingleRecipientMetadata(): EncryptionMetadata {
  return {
    recipientFingerprints: ['AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555'],
    recipientUserIDs: ['Alice <alice@example.com>'],
    encryptedAt: '2025-01-15T10:30:00.000Z',
    keyAlgorithm: 'curve25519',
    recipientCount: 1,
  };
}

function makeMultiRecipientMetadata(): EncryptionMetadata {
  return {
    recipientFingerprints: [
      'AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555',
      'FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000',
      '1111222233334444555566667777888899990000',
    ],
    recipientUserIDs: [
      'Alice <alice@example.com>',
      'Bob <bob@example.com>',
      'Charlie <charlie@example.com>',
    ],
    encryptedAt: '2025-06-20T14:45:30.123Z',
    keyAlgorithm: 'rsa',
    recipientCount: 3,
  };
}

const BLOCK_UUID = 'test-block-uuid-1234';

// --- Unit Tests ---

describe('MetadataWriter Unit Tests', () => {

  // --- Attributes mode tests (Req 14.4, 14.6) ---

  describe('attributes mode', () => {
    it('writes all five block properties with correct keys and values for a single recipient', async () => {
      const writer = new MetadataWriter();
      const metadata = makeSingleRecipientMetadata();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'attributes');

      // getBlock called to retrieve current content
      expect(getBlockMock).toHaveBeenCalledWith(BLOCK_UUID);

      // updateBlock called exactly once
      expect(updateBlockMock).toHaveBeenCalledOnce();

      const updatedContent: string = updateBlockMock.mock.calls[0][1];

      // All five property keys present with correct values
      expect(updatedContent).toContain('encrypted-by:: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555');
      expect(updatedContent).toContain('encrypted-by-uid:: Alice <alice@example.com>');
      expect(updatedContent).toContain('encrypted-at:: 2025-01-15T10:30:00.000Z');
      expect(updatedContent).toContain('encryption-algo:: curve25519');
      expect(updatedContent).toContain('recipient-count:: 1');

      // insertBlock should NOT be called in attributes mode
      expect(insertBlockMock).not.toHaveBeenCalled();
    });

    it('writes comma-separated fingerprints and user IDs for multiple recipients', async () => {
      const writer = new MetadataWriter();
      const metadata = makeMultiRecipientMetadata();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'attributes');

      const updatedContent: string = updateBlockMock.mock.calls[0][1];

      expect(updatedContent).toContain(
        'encrypted-by:: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555, FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000, 1111222233334444555566667777888899990000',
      );
      expect(updatedContent).toContain(
        'encrypted-by-uid:: Alice <alice@example.com>, Bob <bob@example.com>, Charlie <charlie@example.com>',
      );
      expect(updatedContent).toContain('recipient-count:: 3');
    });

    it('appends properties to existing block content', async () => {
      const writer = new MetadataWriter();
      const metadata = makeSingleRecipientMetadata();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'attributes');

      const updatedContent: string = updateBlockMock.mock.calls[0][1];

      // Should start with the original block content
      expect(updatedContent).toMatch(/^-----BEGIN PGP MESSAGE-----/);
      // Properties appended after original content
      expect(updatedContent).toContain('-----END PGP MESSAGE-----\n');
    });
  });

  // --- Sub-blocks mode tests (Req 14.5, 14.6) ---

  describe('sub-blocks mode', () => {
    it('creates five child blocks with correct content for a single recipient', async () => {
      const writer = new MetadataWriter();
      const metadata = makeSingleRecipientMetadata();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'sub-blocks');

      // insertBlock called exactly 5 times
      expect(insertBlockMock).toHaveBeenCalledTimes(5);

      // All calls use sibling: false (child blocks)
      for (const call of insertBlockMock.mock.calls) {
        expect(call[0]).toBe(BLOCK_UUID);
        expect(call[2]).toEqual({ sibling: false });
      }

      const insertedTexts: string[] = insertBlockMock.mock.calls.map((c: any[]) => c[1]);

      expect(insertedTexts).toContain('encrypted-by: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555');
      expect(insertedTexts).toContain('encrypted-by-uid: Alice <alice@example.com>');
      expect(insertedTexts).toContain('encrypted-at: 2025-01-15T10:30:00.000Z');
      expect(insertedTexts).toContain('encryption-algo: curve25519');
      expect(insertedTexts).toContain('recipient-count: 1');

      // updateBlock should NOT be called in sub-blocks mode
      expect(updateBlockMock).not.toHaveBeenCalled();
    });

    it('creates child blocks with comma-separated values for multiple recipients', async () => {
      const writer = new MetadataWriter();
      const metadata = makeMultiRecipientMetadata();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'sub-blocks');

      expect(insertBlockMock).toHaveBeenCalledTimes(5);

      const insertedTexts: string[] = insertBlockMock.mock.calls.map((c: any[]) => c[1]);

      expect(insertedTexts).toContain(
        'encrypted-by: AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555, FFFF6666AAAA7777BBBB8888CCCC9999DDDD0000, 1111222233334444555566667777888899990000',
      );
      expect(insertedTexts).toContain(
        'encrypted-by-uid: Alice <alice@example.com>, Bob <bob@example.com>, Charlie <charlie@example.com>',
      );
      expect(insertedTexts).toContain('recipient-count: 3');
    });
  });

  // --- Metadata with valid input (caller responsibility for metadataEnabled, Req 14.2) ---

  describe('writer behavior with valid input', () => {
    it('always writes metadata when called — disabling is the caller responsibility', async () => {
      const writer = new MetadataWriter();
      const metadata = makeSingleRecipientMetadata();

      // When writeMetadata is called, it always writes regardless of any "enabled" flag
      await writer.writeMetadata(BLOCK_UUID, metadata, 'attributes');
      expect(updateBlockMock).toHaveBeenCalledOnce();

      updateBlockMock.mockClear();
      insertBlockMock.mockClear();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'sub-blocks');
      expect(insertBlockMock).toHaveBeenCalledTimes(5);
    });
  });

  // --- encrypted-at ISO 8601 validation (Req 14.6) ---

  describe('encrypted-at ISO 8601 validation', () => {
    it('attributes mode: encrypted-at value is a valid ISO 8601 string', async () => {
      const writer = new MetadataWriter();
      const metadata = makeSingleRecipientMetadata();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'attributes');

      const updatedContent: string = updateBlockMock.mock.calls[0][1];
      const match = /encrypted-at::\s*(.+)/.exec(updatedContent);
      expect(match).not.toBeNull();

      const dateValue = match![1].trim();
      const parsed = new Date(dateValue);
      expect(parsed.toISOString()).toBe(dateValue);
    });

    it('sub-blocks mode: encrypted-at child block value is a valid ISO 8601 string', async () => {
      const writer = new MetadataWriter();
      const metadata = makeSingleRecipientMetadata();

      await writer.writeMetadata(BLOCK_UUID, metadata, 'sub-blocks');

      const insertedTexts: string[] = insertBlockMock.mock.calls.map((c: any[]) => c[1]);
      const atBlock = insertedTexts.find((t: string) => t.startsWith('encrypted-at:'));
      expect(atBlock).toBeDefined();

      const dateValue = atBlock!.replace('encrypted-at: ', '').trim();
      const parsed = new Date(dateValue);
      expect(parsed.toISOString()).toBe(dateValue);
    });
  });

  // --- recipientCount mismatch validation ---

  describe('recipientCount validation', () => {
    it('throws when recipientCount does not match recipientFingerprints length', async () => {
      const writer = new MetadataWriter();
      const metadata: EncryptionMetadata = {
        ...makeSingleRecipientMetadata(),
        recipientCount: 5, // mismatch: only 1 fingerprint
      };

      await expect(writer.writeMetadata(BLOCK_UUID, metadata, 'attributes')).rejects.toThrow(
        /recipientCount.*does not match/,
      );
    });
  });

  // --- Block not found ---

  describe('block not found', () => {
    it('throws when getBlock returns null in attributes mode', async () => {
      getBlockMock.mockResolvedValueOnce(null);

      const writer = new MetadataWriter();
      const metadata = makeSingleRecipientMetadata();

      await expect(writer.writeMetadata(BLOCK_UUID, metadata, 'attributes')).rejects.toThrow(
        /Block not found/,
      );
    });
  });
});
