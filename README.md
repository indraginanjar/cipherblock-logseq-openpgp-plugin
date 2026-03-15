# CipherBlock – Logseq OpenPGP Plugin

🔐 A Logseq desktop plugin for OpenPGP-compatible encryption and decryption of block content directly within the editor.

## Features

- **Key Management** — Import, list, and remove OpenPGP public and private keys without leaving Logseq
- **Block Encryption** — Encrypt block content for one or more recipients using their public keys
- **Block Decryption** — Decrypt armored PGP messages using your private key
- **Vault Pages** — Encrypt content into isolated vault pages with automatic back-links
- **Output Modes** — Choose where results go: replace the block, insert as sibling, insert as sub-block, or copy to clipboard
- **Encryption Metadata** — Optionally record recipient info, timestamp, and algorithm alongside encrypted content
- **OpenPGP Compatible** — Armored output works with GnuPG 2.x, Kleopatra, and other standard PGP tools

## Installation

### Build from Source

```bash
git clone https://github.com/your-org/logseq-cipherblock.git
cd logseq-cipherblock
npm install
npm run build
```

### Load in Logseq

1. Open Logseq and go to **Settings → Advanced → Developer mode** (enable it)
2. Click **Plugins → Load unpacked plugin**
3. Select the `logseq-cipherblock` project folder
4. The plugin icon 🔐 appears in the toolbar when loaded

## Usage

### Key Management

Use the slash command `/import-key` or access key management through the plugin toolbar to:

- Import armored OpenPGP public or private keys
- View all imported keys (fingerprint, user ID, type, creation date)
- Remove keys from the key store
- Set a default private key for decryption

### Encrypt a Block

1. Place your cursor in the block you want to encrypt
2. Type `/encrypt-block` or right-click and select **Encrypt Block**
3. Select one or more recipient public keys
4. Optionally override the output mode
5. The block content is replaced with (or accompanied by) the armored PGP message

### Decrypt a Block

1. Place your cursor in a block containing an armored PGP message
2. Type `/decrypt-block` or right-click and select **Decrypt Block**
3. The plugin uses your default private key (or prompts you to select one)
4. Enter your passphrase if the key is protected
5. The decrypted plaintext is placed according to your output mode setting

### Encrypt to Vault

1. Place your cursor in the block you want to encrypt
2. Type `/encrypt-to-vault` or right-click and select **Encrypt to Vault**
3. Select recipient public keys
4. A new vault page is created with the encrypted content, and the original block is replaced with a link to the vault page

## Configuration

Access settings via **Logseq → Plugins → CipherBlock → Settings**.

| Option | Type | Default | Description |
|---|---|---|---|
| `defaultKeyFingerprint` | string | `""` | Fingerprint of the private key used for decryption by default |
| `outputMode` | enum | `replace` | Where to place results: `replace`, `sibling`, `sub-block`, or `clipboard` |
| `passphraseCachingEnabled` | boolean | `false` | Cache passphrase in memory for the current session |
| `metadataEnabled` | boolean | `false` | Record recipient info, timestamp, and algorithm alongside encrypted content |
| `metadataMode` | enum | `attributes` | How metadata is written: `attributes` (block properties) or `sub-blocks` (child blocks) |

## License

This project is licensed under the [MIT License](LICENSE).
