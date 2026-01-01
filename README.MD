# 自签名固定证书生成脚本

[![Release](https://img.shields.io/badge/Release-download-brightgreen.svg)](sign-for-your-cert.sh)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

这是一个用于生成私有证书颁发机构 (CA) 、服务器证书及其固定SHA256值的 Shell 脚本，旨在为用VPS自建代理服务的用户，提供无需域名的、支持任意伪装的、严格安全的 TLS 验证，适用于AnyTLS、Trajon等基于TLS的主流协议。

本文档同时提供中英双语版本，[Click here for English documentation](#en-us).

## 项目动机

TLS 类代理协议的安全性完全依赖于 TLS 握手，没有额外加密。在 `server certificate` 阶段，CA 证书用于签名服务器公钥，如果客户端信任由任意机构签名的证书（例如，在客户端选项中“忽略证书验证”），则会产生严重的安全隐患，允许攻击者通过伪造证书执行中间人攻击 (MITM)。

GFW 泄露的代码和工作日志表明，其具备利用伪造证书进行 MITM 攻击以解密 TLS/QUIC 流量的能力。
> 引用：“从现有的代码来看，天狗预载了 tls-ca-bundle.pem 中的公钥用于判断当前流量是否可以进行解密。其判断的逻辑在 TFW 的 ssl-policy 文件夹中。从文件的第 282 行开始决定了当前 SSL 流量是否要被解密。判断的主逻辑则出现在 325 行。这个判断是按照优先级依次进行的。如果命中任何一个，那么天狗都将放弃解密当前流量。如果全部通过则会开始证书替换解密流量。”

本项目旨在通过建立私有信任根来解决此问题。

## 解决方案

此脚本 (`sign-for-your-cert.sh`) 用于建立一个私有的证书颁发机构，同时生成一个根证书 (`rootCA.crt`) 供客户端信任，并用其签发服务器证书 (`server.crt`)，以便用户对伪装的域名强制开启严格的 TLS 验证，同时生成 SHA256 指纹用于证书锁定，防止遭到MITM攻击。

## 功能

-   生成私有根 CA 和服务器证书及私钥。
-   获取用于证书锁定的 SHA256 指纹。
-   自动清理包括 CA 私钥在内的敏感中间文件。

## 环境要求

-   已安装 `openssl`的Ubuntu系统。
-   已安装好简单的代理客户端和代理服务端（面板）。

## 使用方法

### 1. 编辑脚本

打开 `sign-for-your-cert.sh` 文件，修改 `[alt_names]` 部分，使其与您的服务器名称指示 (SNI) 保持一致。

```bash
# 替换为您实际的 SNI
[alt_names]
DNS.1 = your.sni.com
DNS.2 = *.your.sni.com
```

### 2. 运行脚本

```bash
# 赋予执行权限
chmod +x sign-for-your-cert.sh

# 使用 root 权限运行
sudo ./sign-for-your-cert.sh
```

### 3. 配置服务器与客户端

脚本会生成 `server.crt`, `server.key`, `rootCA.crt` 和 `server.txt` 四个文件。

**服务器端:**
-   在您的服务中配置使用 `server.crt` 和 `server.key`。

**客户端:**
1.  在您的客户端设备上导入并信任 `rootCA.crt` 文件。
2.  将 `server.txt` 文件中的 SHA256 哈希值复制并填入客户端的证书锁定配置字段。

## 许可证

本项目基于 MIT 许可证授权。

---

<a name="en-us"></a>

# Self-Signed Pinned Certificate Generator Script

[![Release](https://img.shields.io/badge/Release-download-brightgreen.svg)](sign-for-your-cert.sh)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

This is a shell script for generating a private Certificate Authority (CA), a server certificate, and its pinned SHA256 value. It's designed for users of self-hosted VPS proxy services, providing strictly secure TLS validation that doesn't require a domain name and supports arbitrary SNI spoofing. It is suitable for major TLS-based protocols like AnyTLS, Trojan, etc.

## Threat Model

Standard TLS-based protocols (e.g., Trojan, AnyTLS) depend entirely on the TLS handshake for security. During this process, the CA's signature on the server's public key is verified. If a client is configured to trust any certificate (e.g., "ignore insecure validation"), it becomes vulnerable to sophisticated Man-in-the-Middle (MITM) attacks, where an adversary can forge a certificate to intercept and decrypt all traffic. This risk is especially relevant for users of self-hosted services that may be targeted by state-level actors.

This script mitigates this threat by establishing a private trust anchor.

## Solution

This script (`sign-for-your-cert.sh`) establishes a private Certificate Authority, generates a root certificate (`rootCA.crt`) for client-side trust, and signs a server certificate (`server.crt`) with it. This allows users to enforce strict TLS validation for a spoofed domain, while generating a SHA256 fingerprint for certificate pinning to prevent MITM attacks.

## Features

-   Generates a private Root CA, server certificate, and private key.
-   Obtains the SHA256 fingerprint for certificate pinning.
-   Automates cleanup of sensitive intermediate files, including the CA private key.

## Requirements

-   An Ubuntu system with `openssl` installed.
-   A basic proxy client and server (panel) must already be installed.

## Usage Guide

### 1. Edit the Script

Open `sign-for-your-cert.sh` and modify the `[alt_names]` section to match your Server Name Indication (SNI).

```bash
# Replace with your actual SNI
[alt_names]
DNS.1 = your.sni.com
DNS.2 = *.your.sni.com
```

### 2. Run the Script

```bash
# Grant execution permissions
chmod +x sign-for-your-cert.sh

# Run as root
sudo ./sign-for-your-cert.sh
```

### 3. Configure Server & Client

The script generates: `server.crt`, `server.key`, `rootCA.crt`, and `server.txt`.

**Server-Side:**
-   Configure your service to use `server.crt` and `server.key`.

**Client-Side:**
1.  Import and trust the `rootCA.crt` file on your client device.
2.  Copy the SHA256 hash from `server.txt` into your client's certificate pinning field.

## License

This project is licensed under the MIT License.