# certbot-hook-bmc-ipmi-supermicro

Certbot deploy hook that uploads Let's Encrypt certificates to Supermicro BMC/IPMI interfaces.

## Overview

This script automates the process of uploading SSL certificates to Supermicro server BMCs (Baseboard Management Controllers) via their web interface. It supports multiple generations of Supermicro hardware.

## Supported Models

- **X9** - Older Supermicro boards (uses TLSv1)
- **X10** - Previous generation boards
- **X11** - Current mainstream boards
- **X12** - Latest generation (uses Redfish API)
- **X13** - Treated as X12

## Requirements

- Python 3.6+
- `requests` library
- `pyOpenSSL` library

Install dependencies:

```bash
pip install requests pyOpenSSL
```

## Usage

### As a certbot deploy hook

```bash
certbot renew --deploy-hook "/path/to/ipmi-updater.py \
    --ipmi-url https://ipmi.example.com \
    --model X11 \
    --username ADMIN \
    --password 'your-password' \
    --cert-file \$RENEWED_LINEAGE/fullchain.pem \
    --key-file \$RENEWED_LINEAGE/privkey.pem"
```

### Standalone usage

```bash
./ipmi-updater.py \
    --ipmi-url https://ipmi.example.com \
    --model X11 \
    --username ADMIN \
    --password 'your-password' \
    --cert-file /etc/letsencrypt/live/ipmi.example.com/fullchain.pem \
    --key-file /etc/letsencrypt/live/ipmi.example.com/privkey.pem
```

## Options

| Option | Description |
|--------|-------------|
| `--ipmi-url` | URL of the IPMI web interface (required) |
| `--model` | Board model: X9, X10, X11, X12, X13 (required) |
| `--username` | IPMI admin username (required) |
| `--password` | IPMI admin password (required) |
| `--cert-file` | Path to certificate PEM file (required) |
| `--key-file` | Path to private key PEM file (required) |
| `--no-reboot` | Don't reboot BMC after upload |
| `--no-verify` | Skip certificate verification after reboot |
| `--force-update` | Update even if cert expiry matches |
| `--quiet` | Suppress output on success |
| `--debug` | Enable debug output |

## How it works

1. Logs into the IPMI web interface
2. Checks the current certificate's expiry date
3. Compares with the new certificate's expiry
4. Uploads the new certificate and private key
5. Validates the upload was successful
6. Reboots the BMC to apply changes (unless `--no-reboot`)
7. Waits for BMC to come back online
8. Verifies the new certificate is being served

## Credits

Based on the [Supermicro IPMI certificate updater](https://gist.github.com/HQJaTu/963db9af49d789d074ab63f52061a951) by Jari Turkia ([@HQJaTu](https://github.com/HQJaTu)).

See his blog post for background: [Automating IPMI 2.0 management Let's Encrypt certificate update](https://blog.hqcodeshop.fi/archives/410-Automating-IPMI-2.0-management-Lets-Encrypt-certificate-update.html).

## License

GNU General Public License v2.0 - see [LICENSE](LICENSE)
