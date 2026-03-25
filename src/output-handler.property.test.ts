// CipherBlock – Property-based tests for Output Handler
// Test framework: Vitest with fast-check
// Source: src/output-handler.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fc from 'fast-check';
import { OutputHandler } from './output-handler';
// No additional imports needed beyond OutputHandler

// --- Logseq API & clipboard mock setup ---

let updateBlockMock: ReturnType<typeof vi.fn>;
let insertBlockMock: ReturnType<typeof vi.fn>;
let clipboardWriteTextMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  updateBlockMock = vi.fn(async () => undefined);
  insertBlockMock = vi.fn(async (_uuid: string, _text: string, _opts?: any) => ({
    uuid: 'new-block-uuid',
  }));
  clipboardWriteTextMock = vi.fn(async () => undefined);

  (globalThis as any).logseq = {
    Editor: {
      updateBlock: updateBlockMock,
      insertBlock: insertBlockMock,
    },
  };

  Object.defineProperty(globalThis, 'navigator', {
    value: { clipboard: { writeText: clipboardWriteTextMock } },
    writable: true,
    configurable: true,
  });
});

// --- Arbitraries ---

/** Arbitrary for a block UUID string. */
const blockUuidArb = fc.uuid();

/** Arbitrary for result text (non-empty strings simulating armored messages or plaintext). */
const resultTextArb = fc.string({ minLength: 1, maxLength: 500 });

// --- Property Tests ---

// Feature: logseq-cipherblock, Property 14: Output mode placement
// **Validates: Requirements 5.2, 5.3, 5.4, 5.5, 13.3**
describe('Output Handler Property Tests', () => {
  describe('Property 14: Output mode placement', () => {

    it('replace mode calls updateBlock with the block UUID and result text', async () => {
      const handler = new OutputHandler();

      await fc.assert(
        fc.asyncProperty(blockUuidArb, resultTextArb, async (blockUuid, resultText) => {
          updateBlockMock.mockClear();
          insertBlockMock.mockClear();
          clipboardWriteTextMock.mockClear();

          const returnedUuid = await handler.placeResult(blockUuid, resultText, 'replace');

          // replace mode should call updateBlock with the correct arguments
          expect(updateBlockMock).toHaveBeenCalledOnce();
          expect(updateBlockMock).toHaveBeenCalledWith(blockUuid, resultText);

          // replace mode should NOT call insertBlock or clipboard
          expect(insertBlockMock).not.toHaveBeenCalled();
          expect(clipboardWriteTextMock).not.toHaveBeenCalled();

          // replace mode returns the original block UUID
          expect(returnedUuid).toBe(blockUuid);
        }),
        { numRuns: 100 },
      );
    });

    it('sibling mode calls insertBlock with sibling: true and does not modify the block', async () => {
      const handler = new OutputHandler();

      await fc.assert(
        fc.asyncProperty(blockUuidArb, resultTextArb, async (blockUuid, resultText) => {
          updateBlockMock.mockClear();
          insertBlockMock.mockClear();
          clipboardWriteTextMock.mockClear();

          const returnedUuid = await handler.placeResult(blockUuid, resultText, 'sibling');

          // sibling mode should call insertBlock with sibling: true
          expect(insertBlockMock).toHaveBeenCalledOnce();
          expect(insertBlockMock).toHaveBeenCalledWith(blockUuid, resultText, { sibling: true });

          // sibling mode should NOT call updateBlock (block unchanged) or clipboard
          expect(updateBlockMock).not.toHaveBeenCalled();
          expect(clipboardWriteTextMock).not.toHaveBeenCalled();

          // sibling mode returns the new block's UUID
          expect(returnedUuid).toBe('new-block-uuid');
        }),
        { numRuns: 100 },
      );
    });

    it('sub-block mode calls insertBlock with sibling: false and does not modify the block', async () => {
      const handler = new OutputHandler();

      await fc.assert(
        fc.asyncProperty(blockUuidArb, resultTextArb, async (blockUuid, resultText) => {
          updateBlockMock.mockClear();
          insertBlockMock.mockClear();
          clipboardWriteTextMock.mockClear();

          const returnedUuid = await handler.placeResult(blockUuid, resultText, 'sub-block');

          // sub-block mode should call insertBlock with sibling: false
          expect(insertBlockMock).toHaveBeenCalledOnce();
          expect(insertBlockMock).toHaveBeenCalledWith(blockUuid, resultText, { sibling: false });

          // sub-block mode should NOT call updateBlock (block unchanged) or clipboard
          expect(updateBlockMock).not.toHaveBeenCalled();
          expect(clipboardWriteTextMock).not.toHaveBeenCalled();

          // sub-block mode returns the new block's UUID
          expect(returnedUuid).toBe('new-block-uuid');
        }),
        { numRuns: 100 },
      );
    });

    it('clipboard mode writes to clipboard without modifying the block', async () => {
      const handler = new OutputHandler();

      await fc.assert(
        fc.asyncProperty(blockUuidArb, resultTextArb, async (blockUuid, resultText) => {
          updateBlockMock.mockClear();
          insertBlockMock.mockClear();
          clipboardWriteTextMock.mockClear();

          const returnedUuid = await handler.placeResult(blockUuid, resultText, 'clipboard');

          // clipboard mode should call navigator.clipboard.writeText with the result text
          expect(clipboardWriteTextMock).toHaveBeenCalledOnce();
          expect(clipboardWriteTextMock).toHaveBeenCalledWith(resultText);

          // clipboard mode should NOT call updateBlock or insertBlock (block unchanged)
          expect(updateBlockMock).not.toHaveBeenCalled();
          expect(insertBlockMock).not.toHaveBeenCalled();

          // clipboard mode returns null
          expect(returnedUuid).toBeNull();
        }),
        { numRuns: 100 },
      );
    });
  });
});
