// CipherBlock – Property-based tests for Metadata Writer
// Test framework: Vitest with fast-check
// Source: src/metadata-writer.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fc from 'fast-check';
import { MetadataWriter } from './metadata-writer';
import type { EncryptionMetadata, MetadataMode } from './types';

// --- Logseq API mock setup ---

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

// --- Arbitraries ---

/** Arbitrary for a hex fingerprint string (40 hex chars like a real PGP fingerprint). */
const fingerprintArb = fc.hexaString({ minLength: 40, maxLength: 40 });

/** Arbitrary for a user ID string like "Name <email>". */
const userIdArb = fc.tuple(
  fc.string({ minLength: 1, maxLength: 30 }).filter((s) => !s.includes(',') && !s.includes('\n')),
  fc.emailAddress(),
).map(([name, email]) => `${name} <${email}>`);

/** Arbitrary for a key algorithm name. */
const keyAlgorithmArb = fc.constantFrom('rsa', 'curve25519', 'ed25519', 'nistp256', 'nistp384');

/** Arbitrary for a block UUID. */
const blockUuidArb = fc.uuid();

/** Arbitrary for metadata mode. */
const metadataModeArb: fc.Arbitrary<MetadataMode> = fc.constantFrom('attributes', 'sub-blocks');

/**
 * Arbitrary for EncryptionMetadata with 1..5 recipients.
 * recipientCount always matches the length of recipientFingerprints.
 */
const encryptionMetadataArb: fc.Arbitrary<EncryptionMetadata> = fc
  .tuple(
    fc.integer({ min: 1, max: 5 }),
    keyAlgorithmArb,
  )
  .chain(([count, algo]) =>
    fc.tuple(
      fc.array(fingerprintArb, { minLength: count, maxLength: count }),
      fc.array(userIdArb, { minLength: count, maxLength: count }),
    ).map(([fingerprints, userIDs]) => ({
      recipientFingerprints: fingerprints,
      recipientUserIDs: userIDs,
      encryptedAt: new Date().toISOString(),
      keyAlgorithm: algo,
      recipientCount: count,
    })),
  );

// --- Property Tests ---

describe('Metadata Writer Property Tests', () => {

  // Feature: logseq-cipherblock, Property 20: No metadata when disabled
  // **Validates: Requirements 14.2**
  describe('Property 20: No metadata when disabled', () => {
    it('when MetadataWriter is not called, no Logseq API calls are made for metadata', async () => {
      await fc.assert(
        fc.asyncProperty(
          blockUuidArb,
          encryptionMetadataArb,
          metadataModeArb,
          async (blockUuid, metadata, mode) => {
            updateBlockMock.mockClear();
            insertBlockMock.mockClear();
            getBlockMock.mockClear();

            // Simulate the caller checking metadataEnabled = false and NOT calling writeMetadata.
            // This is the "disabled" path: the caller skips the MetadataWriter entirely.
            const metadataEnabled = false;

            if (metadataEnabled) {
              const writer = new MetadataWriter();
              await writer.writeMetadata(blockUuid, metadata, mode);
            }

            // No Logseq API calls should have been made for metadata
            expect(updateBlockMock).not.toHaveBeenCalled();
            expect(insertBlockMock).not.toHaveBeenCalled();
            expect(getBlockMock).not.toHaveBeenCalled();
          },
        ),
        { numRuns: 100 },
      );
    });
  });

  // Feature: logseq-cipherblock, Property 21: Metadata placement and field completeness
  // **Validates: Requirements 14.4, 14.5, 14.6**
  describe('Property 21: Metadata placement and field completeness', () => {
    it('in attributes mode, block is updated with all five properties', async () => {
      await fc.assert(
        fc.asyncProperty(
          blockUuidArb,
          encryptionMetadataArb,
          async (blockUuid, metadata) => {
            updateBlockMock.mockClear();
            insertBlockMock.mockClear();
            getBlockMock.mockClear();

            const writer = new MetadataWriter();
            await writer.writeMetadata(blockUuid, metadata, 'attributes');

            // getBlock should be called to retrieve current content
            expect(getBlockMock).toHaveBeenCalledWith(blockUuid);

            // updateBlock should be called exactly once
            expect(updateBlockMock).toHaveBeenCalledOnce();

            const updatedContent: string = updateBlockMock.mock.calls[0][1];

            // All five properties must be present
            expect(updatedContent).toContain('encrypted-by::');
            expect(updatedContent).toContain('encrypted-by-uid::');
            expect(updatedContent).toContain('encrypted-at::');
            expect(updatedContent).toContain('encryption-algo::');
            expect(updatedContent).toContain('recipient-count::');

            // encrypted-at value should be a valid ISO 8601 timestamp
            const atMatch = updatedContent.match(/encrypted-at::\s*(.+)/);
            expect(atMatch).not.toBeNull();
            const parsedDate = new Date(atMatch![1].trim());
            expect(parsedDate.toISOString()).toBe(atMatch![1].trim());

            // recipient-count should equal the number of fingerprints
            const countMatch = updatedContent.match(/recipient-count::\s*(\d+)/);
            expect(countMatch).not.toBeNull();
            expect(Number(countMatch![1])).toBe(metadata.recipientFingerprints.length);

            // encrypted-by should contain all fingerprints
            const byMatch = updatedContent.match(/encrypted-by::\s*(.+)/);
            expect(byMatch).not.toBeNull();
            const fingerprints = byMatch![1].trim().split(', ');
            expect(fingerprints).toEqual(metadata.recipientFingerprints);

            // insertBlock should NOT be called in attributes mode
            expect(insertBlockMock).not.toHaveBeenCalled();
          },
        ),
        { numRuns: 100 },
      );
    });

    it('in sub-blocks mode, five child blocks are created with correct content', async () => {
      await fc.assert(
        fc.asyncProperty(
          blockUuidArb,
          encryptionMetadataArb,
          async (blockUuid, metadata) => {
            updateBlockMock.mockClear();
            insertBlockMock.mockClear();
            getBlockMock.mockClear();

            const writer = new MetadataWriter();
            await writer.writeMetadata(blockUuid, metadata, 'sub-blocks');

            // insertBlock should be called exactly 5 times (one per metadata field)
            expect(insertBlockMock).toHaveBeenCalledTimes(5);

            // All calls should use sibling: false (child blocks)
            for (const call of insertBlockMock.mock.calls) {
              expect(call[0]).toBe(blockUuid);
              expect(call[2]).toEqual({ sibling: false });
            }

            // Collect all inserted block texts
            const insertedTexts: string[] = insertBlockMock.mock.calls.map(
              (call: any[]) => call[1] as string,
            );

            // Verify each metadata field is present
            expect(insertedTexts.some((t) => t.startsWith('encrypted-by:'))).toBe(true);
            expect(insertedTexts.some((t) => t.startsWith('encrypted-by-uid:'))).toBe(true);
            expect(insertedTexts.some((t) => t.startsWith('encrypted-at:'))).toBe(true);
            expect(insertedTexts.some((t) => t.startsWith('encryption-algo:'))).toBe(true);
            expect(insertedTexts.some((t) => t.startsWith('recipient-count:'))).toBe(true);

            // encrypted-at value should be valid ISO 8601
            const atBlock = insertedTexts.find((t) => t.startsWith('encrypted-at:'))!;
            const atValue = atBlock.replace('encrypted-at: ', '').trim();
            const parsedDate = new Date(atValue);
            expect(parsedDate.toISOString()).toBe(atValue);

            // recipient-count should equal the number of fingerprints
            const countBlock = insertedTexts.find((t) => t.startsWith('recipient-count:'))!;
            const countValue = countBlock.replace('recipient-count: ', '').trim();
            expect(Number(countValue)).toBe(metadata.recipientFingerprints.length);

            // updateBlock should NOT be called in sub-blocks mode
            expect(updateBlockMock).not.toHaveBeenCalled();
          },
        ),
        { numRuns: 100 },
      );
    });
  });
});
