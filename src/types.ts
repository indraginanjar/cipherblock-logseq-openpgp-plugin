// CipherBlock – Shared type definitions

/** Metadata extracted from parsing an armored OpenPGP key. */
export interface ParsedKey {
  fingerprint: string;
  userID: string;
  type: 'public' | 'private';
  creationDate: Date;
  armoredKey: string;
}

/** In-memory representation of a key stored in the Key Store. */
export interface StoredKey {
  fingerprint: string;
  userID: string;
  type: 'public' | 'private';
  creationDate: Date;
  armoredKey: string;
}

/** Serialized key entry for JSON persistence (creationDate as ISO 8601 string). */
export interface PersistedKeyEntry {
  fingerprint: string;
  userID: string;
  type: 'public' | 'private';
  creationDate: string;
  armoredKey: string;
}

/** Result of an encryption operation. */
export interface EncryptionResult {
  armoredMessage: string;
  recipientCount: number;
}

/** Result of a decryption operation. */
export interface DecryptionResult {
  plaintext: string;
}

/** Placement strategy for encryption/decryption results. */
export type OutputMode = 'replace' | 'sibling' | 'sub-block' | 'clipboard';

/** Result of a vault encryption operation. */
export interface VaultResult {
  vaultPageName: string;
  vaultLink: string;
}

/** Plugin configuration stored in Logseq settings. */
export interface PluginSettings {
  defaultKeyFingerprint: string | null;
  outputMode: OutputMode;
  passphraseCachingEnabled: boolean;
  metadataEnabled: boolean;
  metadataMode: MetadataMode;
}

/** Placement strategy for encryption metadata output. */
export type MetadataMode = 'attributes' | 'sub-blocks';

/** Descriptive fields recorded alongside an encrypted message. */
export interface EncryptionMetadata {
  recipientFingerprints: string[];
  recipientUserIDs: string[];
  encryptedAt: string;
  keyAlgorithm: string;
  recipientCount: number;
}
