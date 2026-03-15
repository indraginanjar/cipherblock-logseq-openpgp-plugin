// CipherBlock – Module boundary interfaces

import type {
  ParsedKey,
  StoredKey,
  EncryptionResult,
  DecryptionResult,
  OutputMode,
  VaultResult,
  PluginSettings,
  EncryptionMetadata,
  MetadataMode,
} from './types';

/** Thin abstraction over OpenPGP.js. All crypto calls go through this interface. */
export interface IOpenPGPAdapter {
  /** Parse an armored key string into structured metadata. Throws on invalid input. */
  parseKey(armoredKey: string): Promise<ParsedKey>;

  /** Encrypt plaintext for one or more recipient public keys. Returns armored message. */
  encrypt(plaintext: string, recipientKeys: string[]): Promise<string>;

  /** Decrypt an armored message using a private key. Passphrase required if key is protected. */
  decrypt(armoredMessage: string, privateKey: string, passphrase?: string): Promise<string>;
}

/** Manages the collection of imported OpenPGP keys. Backed by persistent storage. */
export interface IKeyStore {
  /** Import an armored key. Returns metadata. Throws if invalid or duplicate. */
  importKey(armoredKey: string): Promise<StoredKey>;

  /** Remove a key by fingerprint. Throws if not found. */
  removeKey(fingerprint: string): Promise<void>;

  /** List all stored keys. */
  listKeys(): Promise<StoredKey[]>;

  /** Get a single key by fingerprint. */
  getKey(fingerprint: string): Promise<StoredKey | null>;

  /** List only public keys. */
  getPublicKeys(): Promise<StoredKey[]>;

  /** List only private keys. */
  getPrivateKeys(): Promise<StoredKey[]>;
}

/** Encrypts plaintext for selected recipients. */
export interface IEncryptionService {
  encrypt(plaintext: string, recipientFingerprints: string[]): Promise<EncryptionResult>;
}

/** Decrypts armored messages using a private key. */
export interface IDecryptionService {
  decrypt(
    armoredMessage: string,
    privateKeyFingerprint: string,
    passphraseProvider?: () => Promise<string>,
  ): Promise<DecryptionResult>;
}

/** Places results according to the active output mode. */
export interface IOutputHandler {
  placeResult(blockUuid: string, resultText: string, mode: OutputMode): Promise<void>;
}

/** Orchestrates vault page creation and encrypted storage. */
export interface IVaultService {
  encryptToVault(
    blockUuid: string,
    plaintext: string,
    recipientFingerprints: string[],
  ): Promise<VaultResult>;
}

/** Reads and observes plugin settings. */
export interface ISettingsManager {
  getSettings(): PluginSettings;
  onSettingsChanged(callback: (settings: PluginSettings) => void): void;
}

/** Abstracts persistent key-value storage (wraps Logseq storage API). */
export interface IStorageAdapter {
  /** Read a value by key. Returns null if not found. */
  get(key: string): Promise<string | null>;

  /** Write a value by key. */
  set(key: string, value: string): Promise<void>;

  /** Delete a value by key. */
  remove(key: string): Promise<void>;
}

/** Writes encryption metadata to a block using the configured placement mode. */
export interface IMetadataWriter {
  writeMetadata(
    blockUuid: string,
    metadata: EncryptionMetadata,
    mode: MetadataMode,
  ): Promise<void>;
}
