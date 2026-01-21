#!/bin/bash
set -e
# Clear old files
rm -f *.crt *.key *.conf 
# Generate Root Key
openssl ecparam -genkey -name prime256v1 -out rootCA.key
# Self-sign Root Certificate with Root Key
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 36500 \
-out rootCA.crt -subj "/C=CN/O=Global Trust/CN=My Root CA"
# Generate Server Key
openssl ecparam -genkey -name prime256v1 -out server.key
# Create Server Cert Config
cat > server.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
# Please replace a.com and *.a.com with your SNI values
[alt_names]
DNS.1 = a.com
DNS.2 = *.a.com
EOF

# C=Country, L=Location, O=Organization, CN=Common Name; generate CSR with server key
openssl req -new -key server.key -out server.csr \
-subj "/C=CN/ST=Beijing/L=Beijing/O=Speedtest/CN=speedtest.cn"

# Sign Server Cert with Root CA key and cert
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key \
-CAcreateserial -out server.crt -days 3650 -sha256 -extfile server.ext
# Remove Root Key to prevent MITM if leaked
# Remove intermediate files
rm -rf rootCA.key server.ext server.csr
# Convert cert to binary -> SHA256 -> Base64 output
openssl x509 -in server.crt -outform DER | openssl dgst -sha256 -binary | openssl base64 > server.txt

echo "----------------------------------------"
echo "Generation Complete:"
# List files
ls -lh server.crt server.key rootCA.crt server.txt
echo "----------------------------------------"