import { OpenPGPAdapter } from './openpgp-adapter';
import { StorageAdapter } from './storage-adapter';
import { KeyStore } from './key-store';
import { SettingsManager } from './settings-manager';
import { EncryptionService } from './encryption-service';
import { DecryptionService } from './decryption-service';
import { OutputHandler } from './output-handler';
import { MetadataWriter } from './metadata-writer';
import { VaultService } from './vault-service';
import { registerCommands } from './commands';

async function main() {
  // Instantiate adapters
  const pgpAdapter = new OpenPGPAdapter();
  const storageAdapter = new StorageAdapter();

  // Instantiate core services
  const keyStore = new KeyStore(pgpAdapter, storageAdapter);
  const settingsManager = new SettingsManager(keyStore);
  const encryptionService = new EncryptionService(pgpAdapter, keyStore);
  const decryptionService = new DecryptionService(pgpAdapter, keyStore);
  const outputHandler = new OutputHandler();
  const metadataWriter = new MetadataWriter();
  const vaultService = new VaultService(encryptionService, settingsManager, metadataWriter, keyStore);

  // Register settings schema
  settingsManager.registerSchema();

  // Register all commands
  registerCommands({
    keyStore,
    encryptionService,
    decryptionService,
    vaultService,
    outputHandler,
    settingsManager,
    metadataWriter,
  });

  console.log('CipherBlock plugin loaded');
}

logseq.ready(main).catch(console.error);
