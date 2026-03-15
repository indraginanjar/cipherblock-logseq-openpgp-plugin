import { CipherBlockError, PassphraseError } from './errors';

/** Safe wrapper around logseq.UI.showMsg that swallows internal Logseq errors. */
function notify(msg: string, status?: 'success' | 'warning' | 'error'): void {
  try {
    logseq.UI.showMsg(msg, status).catch(() => {});
  } catch {
    // Swallow synchronous errors
  }
}

export function handleError(error: unknown): void {
  // Silently ignore user cancellations
  if (error instanceof PassphraseError && error.userMessage.includes('cancelled')) {
    return;
  }

  if (error instanceof CipherBlockError) {
    notify(error.userMessage, 'error');
    console.error('[CipherBlock]', error.userMessage, error.cause ?? error);
  } else {
    const msg = error instanceof Error ? error.message : String(error);
    notify(`CipherBlock error: ${msg}`, 'error');
    console.error('[CipherBlock] Unexpected error:', error);
    if (error instanceof Error && error.stack) {
      console.error('[CipherBlock] Stack:', error.stack);
    }
  }
}
