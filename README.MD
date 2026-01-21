# Self-Signed Certificate Generator for Certificate Pinning

[![Release](https://img.shields.io/badge/Release-download-brightgreen.svg)](sign-for-your-cert.sh)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

![CertLite Screenshot](image.png)

This is a shell script designed to generate a private Certificate Authority (CA), a server certificate, and its corresponding SHA256 fingerprint. It aims to provide strict, secure TLS verification for users deploying self-hosted proxy services on a VPS without requiring a registered domain name. It supports arbitrary SNI masquerading and is compatible with mainstream TLS-based protocols such as AnyTLS and Trojan.

[Click here for Chinese docs](#zh-cn)

## Motivation

The security of TLS-based proxy protocols relies entirely on the TLS handshake, as there is no additional encryption layer. During the `server certificate` phase, a CA certificate signs the server's public key. If a client is configured to trust arbitrary certificates (e.g., by enabling "Skip Certificate Verification" or "Allow Insecure"), it creates a critical vulnerability. This allows attackers to perform Man-in-the-Middle (MITM) attacks by forging certificates to intercept traffic.

Leaked code and operational logs from the GFW suggest it possesses the capability to use forged certificates for MITM attacks to decrypt TLS/QUIC traffic.
> "Judging from the existing code, 'Tiangou' preloads public keys from `tls-ca-bundle.pem` to determine if the current traffic can be decrypted. The logic resides in TFW's `ssl-policy` folder. The decision process starts at line 282... The main logic appears at line 325. This judgment is performed sequentially based on priority... If all checks pass, it will initiate certificate replacement to decrypt the traffic."

This project aims to solve this problem by establishing a private root of trust.

## Solution

This tool establishes a private Certificate Authority (CA) to generate a root certificate (`rootCA.crt`) for client-side trust. It then uses this root to sign a server certificate (`server.crt`). This allows users to enforce strict TLS verification on masqueraded domains while generating a SHA256 fingerprint for certificate pinning, effectively preventing MITM attacks.

## Features

-   Generates a private Root CA, a server certificate, and a private key.
-   Extracts the SHA256 fingerprint required for certificate pinning.
-   Automatically cleans up sensitive intermediate files (including the CA private key).
-   **New!** Windows GUI Version available.

## Requirements

-   **Linux/macOS**: `openssl`
-   **Windows**: Python 3 + `ttkbootstrap` (included in `run_cert_lite.bat`)

## Usage

### Windows GUI (CertLite)

1.  Double-click `run_cert_lite.bat`.
2.  Enter your Domain/IP.
3.  Select Output Directory.
4.  Click **Generate**.

### Linux / macOS (Shell Script)

#### 1. Edit the Script

Open the `sign-for-your-cert.sh` file and modify the `[alt_names]` section to ensure it matches your Server Name Indication (SNI).

```bash
# Replace with your actual SNI
[alt_names]
DNS.1 = your.sni.com
DNS.2 = *.your.sni.com
```

#### 2. Run the Script

```bash
# Grant execution permissions
chmod +x sign-for-your-cert.sh

# Run with root privileges
sudo ./sign-for-your-cert.sh
```

### 3. Configure Server & Client

The tools will generate four files: `server.crt`, `server.key`, `rootCA.crt`, and `server.txt` (or valid output).

**Server-side:**
-   Configure your service to use `server.crt` and `server.key`.

**Client-side:**
1.  Import and trust the `rootCA.crt` file on your client device.
2.  Copy the SHA256 hash value from the `server.txt` file (or GUI status) and enter it into your client's certificate pinning configuration field.

## License

This project is licensed under the MIT License.