// CipherBlock – Property-based tests for Error Handler
// Test framework: Vitest with fast-check
// Source: src/error-handler.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fc from 'fast-check';
import { handleError } from './error-handler';
import {
  CipherBlockError,
  KeyImportError,
  DuplicateKeyError,
  EmptyBlockError,
  InvalidCiphertextError,
  DecryptionError,
  KeyMismatchError,
  PassphraseError,
  NoKeysError,
  ClipboardError,
  LogseqApiError,
} from './errors';

// --- Logseq API & console mock setup ---

let showMsgMock: ReturnType<typeof vi.fn>;
let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  showMsgMock = vi.fn(async () => undefined);

  (globalThis as any).logseq = {
    UI: {
      showMsg: showMsgMock,
    },
  };

  consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
});

// --- Arbitraries ---

/** Arbitrary for a non-empty user message string (excluding 'cancelled' to avoid silent ignore path). */
const userMessageArb = fc.string({ minLength: 1, maxLength: 200 }).filter(
  (s) => !s.includes('cancelled'),
);

/** Arbitrary for an optional cause Error. */
const causeErrorArb = fc.option(
  fc.string({ minLength: 1, maxLength: 100 }).map((msg) => new Error(msg)),
  { nil: undefined },
);

/** Arbitrary for a random CipherBlockError subclass instance. */
const cipherBlockErrorArb = fc.tuple(userMessageArb, causeErrorArb).chain(([userMessage, cause]) => {
  const errorConstructors = [
    CipherBlockError,
    KeyImportError,
    DuplicateKeyError,
    EmptyBlockError,
    InvalidCiphertextError,
    DecryptionError,
    KeyMismatchError,
    NoKeysError,
    ClipboardError,
    LogseqApiError,
  ];
  return fc.constantFrom(...errorConstructors).map(
    (Ctor) => new Ctor(userMessage, cause),
  );
});

/** Arbitrary for unknown (non-CipherBlockError) errors. */
const unknownErrorArb = fc.oneof(
  fc.string({ minLength: 1, maxLength: 200 }).map((msg) => new Error(msg)),
  fc.string({ minLength: 1, maxLength: 200 }).map((msg) => new TypeError(msg)),
  fc.string({ minLength: 1, maxLength: 200 }).map((msg) => new RangeError(msg)),
  fc.string({ minLength: 1, maxLength: 200 }),
  fc.integer(),
);

// --- Property Tests ---

// Feature: logseq-cipherblock, Property 17: Error handler produces user message and console log
// **Validates: Requirements 11.3**
describe('Error Handler Property Tests', () => {
  describe('Property 17: Error handler produces user message and console log', () => {

    it('for any CipherBlockError, handler shows userMessage and logs cause', async () => {
      await fc.assert(
        fc.asyncProperty(cipherBlockErrorArb, async (error) => {
          showMsgMock.mockClear();
          consoleErrorSpy.mockClear();

          handleError(error);

          // Should show the userMessage via logseq.UI.showMsg with 'error' status
          expect(showMsgMock).toHaveBeenCalledOnce();
          expect(showMsgMock).toHaveBeenCalledWith(error.userMessage, 'error');

          // Should log to console.error with the cause (or the error itself if no cause)
          expect(consoleErrorSpy).toHaveBeenCalled();
          const firstCallArgs = consoleErrorSpy.mock.calls[0];
          expect(firstCallArgs[0]).toBe('[CipherBlock]');
          expect(firstCallArgs[1]).toBe(error.userMessage);
          expect(firstCallArgs[2]).toBe(error.cause ?? error);
        }),
        { numRuns: 100 },
      );
    });

    it('for unknown errors, handler shows generic message and logs full error', async () => {
      await fc.assert(
        fc.asyncProperty(unknownErrorArb, async (error) => {
          showMsgMock.mockClear();
          consoleErrorSpy.mockClear();

          handleError(error);

          // Should show a generic error message via logseq.UI.showMsg
          expect(showMsgMock).toHaveBeenCalledOnce();
          const expectedMsg =
            error instanceof Error
              ? `CipherBlock error: ${error.message}`
              : `CipherBlock error: ${String(error)}`;
          expect(showMsgMock).toHaveBeenCalledWith(expectedMsg, 'error');

          // Should log the full error to console.error
          expect(consoleErrorSpy).toHaveBeenCalled();
          const firstCallArgs = consoleErrorSpy.mock.calls[0];
          expect(firstCallArgs[0]).toBe('[CipherBlock] Unexpected error:');
          expect(firstCallArgs[1]).toBe(error);
        }),
        { numRuns: 100 },
      );
    });

    it('PassphraseError with "cancelled" in message is silently ignored', async () => {
      // This verifies the special cancellation path doesn't show UI or log
      const cancelledMessageArb = fc.string({ minLength: 0, maxLength: 100 }).map(
        (prefix) => `${prefix}cancelled${prefix}`,
      );

      await fc.assert(
        fc.asyncProperty(cancelledMessageArb, causeErrorArb, async (msg, cause) => {
          showMsgMock.mockClear();
          consoleErrorSpy.mockClear();

          const error = new PassphraseError(msg, cause);
          handleError(error);

          // Should NOT show any message or log anything
          expect(showMsgMock).not.toHaveBeenCalled();
          expect(consoleErrorSpy).not.toHaveBeenCalled();
        }),
        { numRuns: 100 },
      );
    });
  });
});
