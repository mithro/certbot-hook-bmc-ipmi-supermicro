# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Certbot deploy hook that uploads Let's Encrypt SSL certificates to Supermicro BMC/IPMI interfaces. Supports X9, X10, X11, X12, and X13 board generations with model-specific protocols.

## Running the Script

```bash
# Install dependencies
uv pip install requests pyOpenSSL

# Standalone usage
uv run ipmi-updater.py \
    --ipmi-url https://ipmi.example.com \
    --model X11 \
    --username ADMIN \
    --password 'password' \
    --cert-file /path/to/fullchain.pem \
    --key-file /path/to/privkey.pem

# With certbot
certbot renew --deploy-hook "/path/to/ipmi-updater.py --ipmi-url ... --cert-file \$RENEWED_LINEAGE/fullchain.pem --key-file \$RENEWED_LINEAGE/privkey.pem"
```

## Architecture

Single-file Python script (`ipmi-updater.py`) with class hierarchy for board-specific protocols:

- **`IPMIUpdater`** - Base class with common login, CSRF handling, cert info retrieval, upload, and reboot logic
- **`IPMIX9Updater`** - Older boards requiring TLSv1 via custom HTTPAdapter
- **`IPMIX10Updater`** - Previous generation, uses XML-based API at `/cgi/BMCReset.cgi`
- **`IPMIX11Updater`** - Current mainstream, uses `/cgi/op.cgi` for operations
- **`IPMIX12Updater`** - Latest generation using Redfish API at `/redfish/v1/...`

X13 boards are treated as X12.

## Key Implementation Details

- **Authentication**: X9-X11 use form-based login to `/cgi/login.cgi` (some with base64-encoded credentials). X12 uses JSON to Redfish SessionService and returns auth token in `X-Auth-Token` header.
- **CSRF Protection**: Non-X12 models require CSRF token extraction from page JavaScript (`SmcCsrfInsert`).
- **Certificate Handling**: Strips DH params from PEM files; X12 requires single certificate only (splits at first `END CERTIFICATE`).
- **Verification**: After upload, validates via `SSL_VALIDATE.XML` endpoint (non-X12). Post-reboot verification compares certificate expiry dates.
