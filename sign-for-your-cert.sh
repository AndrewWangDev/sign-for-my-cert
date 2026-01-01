#!/bin/bash
set -e
#清除旧文件
rm -f *.crt *.key *.conf 
#生成根证书私钥
openssl ecparam -genkey -name prime256v1 -out rootCA.key
#用rootCA.key对根证书自签名
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 36500 \
-out rootCA.crt -subj "/C=CN/O=Global Trust/CN=My Root CA"
#生成服务器私钥
openssl ecparam -genkey -name prime256v1 -out server.key
#创建服务器证书配置文件
cat > server.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
#请将a.com和*.a.com替换为代理协议中SNI的值
[alt_names]
DNS.1 = a.com
DNS.2 = *.a.com
EOF

#C为国家/地区，L为位置，O为组织，CN为通用名称，证书和服务器公钥一起生成签名请求
openssl req -new -key server.key -out server.csr \
-subj "/C=CN/ST=Beijing/L=Beijing/O=Speedtest/CN=speedtest.cn"

# 用CA私钥对服务器证书和服务器公钥签名
openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key \
-CAcreateserial -out server.crt -days 3650 -sha256 -extfile server.ext
# 清除根证书私钥，防止泄漏后被用于MITM
# 清除无关文件
rm -rf rootCA.key server.ext server.csr
# 将证书->二进制格式->SHA256哈希->base64编码后输出
openssl x509 -in server.crt -outform DER | openssl dgst -sha256 -binary | openssl base64 > server.txt

echo "----------------------------------------"
echo "生成完毕："
#查看
ls -lh server.crt server.key rootCA.crt server.txt
echo "----------------------------------------"