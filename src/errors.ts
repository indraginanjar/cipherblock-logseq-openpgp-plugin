// CipherBlock – Typed error classes

/** Base error for all CipherBlock operations. Carries a user-facing message and optional cause. */
export class CipherBlockError extends Error {
  constructor(
    public readonly userMessage: string,
    public readonly cause?: Error,
  ) {
    super(userMessage);
    this.name = 'CipherBlockError';
  }
}

/** Thrown when an armored key cannot be parsed or is unsupported. */
export class KeyImportError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'KeyImportError';
  }
}

/** Thrown when importing a key whose fingerprint already exists in the Key Store. */
export class DuplicateKeyError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'DuplicateKeyError';
  }
}

/** Thrown when attempting to encrypt an empty or whitespace-only block. */
export class EmptyBlockError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'EmptyBlockError';
  }
}

/** Thrown when a block does not contain a valid OpenPGP armored message. */
export class InvalidCiphertextError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'InvalidCiphertextError';
  }
}

/** Thrown when decryption fails for a general reason. */
export class DecryptionError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'DecryptionError';
  }
}

/** Thrown when the selected private key cannot decrypt the message. */
export class KeyMismatchError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'KeyMismatchError';
  }
}

/** Thrown when an incorrect passphrase is provided for a protected key. */
export class PassphraseError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'PassphraseError';
  }
}

/** Thrown when no keys of the required type exist in the Key Store. */
export class NoKeysError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'NoKeysError';
  }
}

/** Thrown when a clipboard write operation fails. */
export class ClipboardError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'ClipboardError';
  }
}

/** Thrown when a Logseq API call fails. */
export class LogseqApiError extends CipherBlockError {
  constructor(userMessage: string, cause?: Error) {
    super(userMessage, cause);
    this.name = 'LogseqApiError';
  }
}
