import { CipherBlockError } from './errors';

export function handleError(error: unknown): void {
  if (error instanceof CipherBlockError) {
    logseq.UI.showMsg(error.userMessage, 'error');
    console.error(error.cause ?? error);
  } else {
    logseq.UI.showMsg('An unexpected error occurred', 'error');
    console.error(error);
  }
}
