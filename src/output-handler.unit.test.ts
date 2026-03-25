// CipherBlock – Unit tests for Output Handler
// Test framework: Vitest
// Source: src/output-handler.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { OutputHandler } from './output-handler';
import { ClipboardError } from './errors';

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

// --- Unit Tests ---

describe('Output Handler Unit Tests', () => {
  // **Validates: Requirements 5.2, 13.1**
  describe('replace mode', () => {
    it('calls updateBlock with the correct blockUuid and resultText', async () => {
      const handler = new OutputHandler();
      const result = await handler.placeResult('block-123', 'encrypted content', 'replace');

      expect(updateBlockMock).toHaveBeenCalledOnce();
      expect(updateBlockMock).toHaveBeenCalledWith('block-123', 'encrypted content');
      expect(insertBlockMock).not.toHaveBeenCalled();
      expect(clipboardWriteTextMock).not.toHaveBeenCalled();
      expect(result).toBe('block-123');
    });
  });

  // **Validates: Requirements 5.3, 13.1**
  describe('sibling mode', () => {
    it('calls insertBlock with sibling: true', async () => {
      const handler = new OutputHandler();
      const result = await handler.placeResult('block-456', 'decrypted text', 'sibling');

      expect(insertBlockMock).toHaveBeenCalledOnce();
      expect(insertBlockMock).toHaveBeenCalledWith('block-456', 'decrypted text', { sibling: true });
      expect(updateBlockMock).not.toHaveBeenCalled();
      expect(clipboardWriteTextMock).not.toHaveBeenCalled();
      expect(result).toBe('new-block-uuid');
    });
  });

  // **Validates: Requirements 5.4, 13.1**
  describe('sub-block mode', () => {
    it('calls insertBlock with sibling: false', async () => {
      const handler = new OutputHandler();
      const result = await handler.placeResult('block-789', 'child content', 'sub-block');

      expect(insertBlockMock).toHaveBeenCalledOnce();
      expect(insertBlockMock).toHaveBeenCalledWith('block-789', 'child content', { sibling: false });
      expect(updateBlockMock).not.toHaveBeenCalled();
      expect(clipboardWriteTextMock).not.toHaveBeenCalled();
      expect(result).toBe('new-block-uuid');
    });
  });

  // **Validates: Requirements 5.5, 13.1**
  describe('clipboard mode', () => {
    it('calls navigator.clipboard.writeText with the result text', async () => {
      const handler = new OutputHandler();
      const result = await handler.placeResult('block-abc', 'clipboard text', 'clipboard');

      expect(clipboardWriteTextMock).toHaveBeenCalledOnce();
      expect(clipboardWriteTextMock).toHaveBeenCalledWith('clipboard text');
      expect(updateBlockMock).not.toHaveBeenCalled();
      expect(insertBlockMock).not.toHaveBeenCalled();
      expect(result).toBeNull();
    });
  });

  // **Validates: Requirements 13.2, 9.4**
  describe('clipboard failure', () => {
    it('throws ClipboardError when navigator.clipboard.writeText rejects', async () => {
      clipboardWriteTextMock.mockRejectedValueOnce(new Error('Clipboard access denied'));

      const handler = new OutputHandler();

      try {
        await handler.placeResult('block-err', 'text', 'clipboard');
        expect.unreachable('Should have thrown ClipboardError');
      } catch (err) {
        expect(err).toBeInstanceOf(ClipboardError);
        expect((err as ClipboardError).userMessage).toBe('Failed to copy to clipboard');
        expect((err as ClipboardError).cause).toBeInstanceOf(Error);
        expect((err as ClipboardError).cause!.message).toBe('Clipboard access denied');
      }
    });
  });
});
