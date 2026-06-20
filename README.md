# Yaak TOTP Generator

Generate Time-based One-Time Password (TOTP) and Steam codes directly inside Yaak.

## Features

- **TOTP codes** — RFC 6238 compliant (6–8 digits)
- **Steam codes** — 5-character alphanumeric codes
- **Multiple input formats** — Base32, Hex, or raw Text secret
- **Algorithm support** — SHA1, SHA256, SHA512
- **Configurable period** — 15s, 30s, or 60s
- **Verification window** — check adjacent time steps for clock drift
- **Verify function** — validate a TOTP code against a secret

## Installation

1. Open Yaak → **Settings** → **Plugins**
2. Click **Install** and select the plugin directory
3. The plugin will appear as "TOTP Generator"

## Usage

### Generate a TOTP code

Insert `{[ otp.generate ]}` in any text field. A configuration dialog will open where you can set:

| Field | Description |
|---|---|
| Secret Key | The shared secret (Base32, Hex, or Text) |
| Input Format | How the secret is encoded |
| Code Type | TOTP or Steam |
| Algorithm | SHA1, SHA256, SHA512 |
| Digits | 6, 7, or 8 (TOTP only) |
| Period | Time step in seconds (TOTP only) |
| Custom Timestamp | Unix timestamp in milliseconds (optional) |
| Verification Window | Number of time steps to check (1–3) |

### Verify a TOTP code

Insert `{[ otp.verify ]}` to check if a given code is valid for a secret. Returns `true` or `false`.

### Examples

```
Bearer {[ otp.generate ]}
```

```
X-TOTP: {[ otp.verify ]}
```

## Development

```sh
npm install -g @yaakapp/cli
npm install
npm run dev    # watch mode
npm run build  # production build
```

## License

MIT
