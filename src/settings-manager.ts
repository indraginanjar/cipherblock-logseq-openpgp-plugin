// CipherBlock – Settings Module implementation

import type { ISettingsManager, IKeyStore } from './interfaces';
import type { PluginSettings, OutputMode, MetadataMode } from './types';

/** Settings schema for registration with logseq.useSettingsSchema(). */
export const settingsSchema = [
  {
    key: 'defaultKeyFingerprint',
    type: 'string',
    default: '',
    title: 'Default Private Key Fingerprint',
    description: 'Fingerprint of the private key used for decryption by default.',
  },
  {
    key: 'outputMode',
    type: 'enum',
    default: 'replace',
    enumChoices: ['replace', 'sibling', 'sub-block', 'clipboard'],
    title: 'Default Output Mode',
    description: 'Where to place encryption/decryption results.',
  },
  {
    key: 'passphraseCachingEnabled',
    type: 'boolean',
    default: false,
    title: 'Cache Passphrase for Session',
    description:
      'When enabled, the passphrase is cached in memory for the current session.',
  },
  {
    key: 'metadataEnabled',
    type: 'boolean',
    default: false,
    title: 'Write Encryption Metadata',
    description:
      'When enabled, records recipient info, timestamp, and algorithm alongside encrypted content.',
  },
  {
    key: 'metadataMode',
    type: 'enum',
    default: 'attributes',
    enumChoices: ['attributes', 'sub-blocks'],
    title: 'Metadata Placement Mode',
    description:
      'How metadata is written: as Logseq block properties (attributes) or as child blocks (sub-blocks).',
  },
];

/**
 * Reads and observes plugin settings via the Logseq settings API.
 * Supports auto-designating a single private key as the default.
 */
export class SettingsManager implements ISettingsManager {
  constructor(private readonly keyStore: IKeyStore) {}

  /** Register the settings schema with Logseq so options appear in the Settings UI. */
  registerSchema(): void {
    logseq.useSettingsSchema(settingsSchema);
  }

  getSettings(): PluginSettings {
    const raw = logseq.settings ?? {};

    const fingerprint = raw['defaultKeyFingerprint'] as string | undefined;

    return {
      defaultKeyFingerprint: fingerprint || null,
      outputMode: (raw['outputMode'] as OutputMode) ?? 'replace',
      passphraseCachingEnabled: (raw['passphraseCachingEnabled'] as boolean) ?? false,
      metadataEnabled: (raw['metadataEnabled'] as boolean) ?? false,
      metadataMode: (raw['metadataMode'] as MetadataMode) ?? 'attributes',
    };
  }

  /**
   * Get settings with auto-designation of a single private key as default.
   * If defaultKeyFingerprint is null and exactly one private key exists,
   * that key's fingerprint is returned as the default.
   */
  async getSettingsWithAutoDefault(): Promise<PluginSettings> {
    const settings = this.getSettings();

    if (settings.defaultKeyFingerprint === null) {
      const privateKeys = await this.keyStore.getPrivateKeys();
      if (privateKeys.length === 1) {
        return {
          ...settings,
          defaultKeyFingerprint: privateKeys[0].fingerprint,
        };
      }
    }

    return settings;
  }

  onSettingsChanged(callback: (settings: PluginSettings) => void): void {
    logseq.onSettingsChanged((_newSettings: Record<string, unknown>) => {
      callback(this.getSettings());
    });
  }
}
