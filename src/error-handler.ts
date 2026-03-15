import { CipherBlockError } from './errors';

export function handleError(error: unknown): void {
  if (error instanceof CipherBlockError) {
    logseq.UI.showMsg(error.userMessage, 'error');
    console.error('[CipherBlock]', error.userMessage, error.cause ?? error);
  } else {
    const msg = error instanceof Error ? error.message : String(error);
    logseq.UI.showMsg(`CipherBlock error: ${msg}`, 'error');
    console.error('[CipherBlock] Unexpected error:', error);
    if (error instanceof Error && error.stack) {
      console.error('[CipherBlock] Stack:', error.stack);
    }
  }
}
