// CipherBlock – Unit tests for Error Handler
// Test framework: Vitest
// Source: src/error-handler.ts

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { handleError } from './error-handler';
import {
  CipherBlockError,
  KeyImportError,
  DecryptionError,
  PassphraseError,
} from './errors';

// --- Logseq API & console mock setup (same pattern as property test) ---

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

// --- Unit Tests ---

describe('Error Handler Unit Tests', () => {
  describe('CipherBlockError shows userMessage', () => {
    it('displays userMessage via logseq.UI.showMsg for a CipherBlockError', () => {
      const error = new CipherBlockError('Key import failed');
      handleError(error);

      expect(showMsgMock).toHaveBeenCalledOnce();
      expect(showMsgMock).toHaveBeenCalledWith('Key import failed', 'error');
    });

    it('displays userMessage for a CipherBlockError subclass', () => {
      const error = new KeyImportError('Malformed armor header');
      handleError(error);

      expect(showMsgMock).toHaveBeenCalledOnce();
      expect(showMsgMock).toHaveBeenCalledWith('Malformed armor header', 'error');
    });
  });

  describe('unknown Error shows generic message', () => {
    it('displays generic message for a plain Error', () => {
      const error = new Error('something broke');
      handleError(error);

      expect(showMsgMock).toHaveBeenCalledOnce();
      expect(showMsgMock).toHaveBeenCalledWith('CipherBlock error: something broke', 'error');
    });

    it('displays generic message for a string error', () => {
      handleError('raw string error');

      expect(showMsgMock).toHaveBeenCalledOnce();
      expect(showMsgMock).toHaveBeenCalledWith('CipherBlock error: raw string error', 'error');
    });

    it('displays generic message for a number error', () => {
      handleError(42);

      expect(showMsgMock).toHaveBeenCalledOnce();
      expect(showMsgMock).toHaveBeenCalledWith('CipherBlock error: 42', 'error');
    });
  });

  describe('console.error is called with cause', () => {
    it('logs cause when CipherBlockError has a cause', () => {
      const cause = new Error('underlying issue');
      const error = new DecryptionError('Decryption failed', cause);
      handleError(error);

      expect(consoleErrorSpy).toHaveBeenCalledWith('[CipherBlock]', 'Decryption failed', cause);
    });

    it('logs the error itself when CipherBlockError has no cause', () => {
      const error = new CipherBlockError('No cause here');
      handleError(error);

      expect(consoleErrorSpy).toHaveBeenCalledWith('[CipherBlock]', 'No cause here', error);
    });

    it('logs full error for unknown Error', () => {
      const error = new TypeError('unexpected type');
      handleError(error);

      expect(consoleErrorSpy).toHaveBeenCalledWith('[CipherBlock] Unexpected error:', error);
    });

    it('logs stack trace for unknown Error with stack', () => {
      const error = new Error('has stack');
      handleError(error);

      expect(consoleErrorSpy).toHaveBeenCalledWith('[CipherBlock] Unexpected error:', error);
      expect(consoleErrorSpy).toHaveBeenCalledWith('[CipherBlock] Stack:', error.stack);
    });
  });

  describe('PassphraseError cancellation is silently ignored', () => {
    it('does not show message or log for cancelled passphrase', () => {
      const error = new PassphraseError('Decryption cancelled');
      handleError(error);

      expect(showMsgMock).not.toHaveBeenCalled();
      expect(consoleErrorSpy).not.toHaveBeenCalled();
    });
  });
});
