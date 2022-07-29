#!/usr/bin/env bash

# 根证书
# if [[ ! -d "certs" ]];then
#   mkdir certs crl newcerts private
#   chmod 700 private
#   touch index.txt
#   echo 1000 > serial
# fi
# cat <<EOF
# -------------------- Notes Below --------------------
# Enter pass phrase for ca.key.pem: passphrase
# Verifying - Enter pass phrase for ca.key.pem: passphrase
# -------------------- Notes Above --------------------
# EOF
# openssl genrsa -aes256 -out private/ca.key.pem 4096 # passphrase:passphrase
# chmod 400 private/ca.key.pem

# # $1='D:/homework-2022-s/XiaoXueQI/zcfxc/CUC/whatever/cuc/x.509'
# cat <<EOF
# -------------------- Notes Below --------------------
# Enter pass phrase for ca.key.pem: passphrase
# You are about to be asked to enter information that will be incorporated
# into your certificate request.
# -----
# Country Name (2 letter code) [XX]:CN
# State or Province Name []:Beijing
# Locality Name []:Chaoyang
# Organization Name []:WhateverItIs
# Organizational Unit Name []:School of Computer Science and Cybersecurity
# Common Name []:WhaterverRoot CA
# Email Address []:admin@a101e.lab
# -------------------- Notes Above --------------------
# EOF
# if [[ ! -f "openssl.cnf" ]];then
#   cat "openssl.cnf.example" | sed "s#<CA_default_dir>#$PWD#g"  > "openssl.cnf"
# fi
# # Common Name []:WhaterverRoot CA
# openssl req -config openssl.cnf \
#       -key private/ca.key.pem \
#       -new -x509 -days 7300 -sha256 -extensions v3_ca \
#       -out certs/ca.cert.crt



# # 中间证书
# if [[ ! -d "intermediate/private" ]];then
#   cd intermediate
#   mkdir certs crl csr newcerts private
#   chmod 700 private
#   touch index.txt
#   echo 1000 > serial
#   echo 1000 > ../crlnumber
#   cd ..
# fi

# cat <<EOF
# -------------------- Notes Below --------------------
# Enter pass phrase for intermediate.key.pem: passphrase
# Verifying - Enter pass phrase for intermediate.key.pem: passphrase
# -------------------- Notes Above --------------------
# Enter pass phrase for intermediate.key.pem: passphrase
# EOF

# if [[ ! -f "intermediate/private/intermediate.key.pem" ]];then

# openssl genrsa -aes256 \
#       -out intermediate/private/intermediate.key.pem 4096  # passphrase:passphrase

# chmod 400 intermediate/private/intermediate.key.pem

#     if [[ ! -f "intermediate/openssl.cnf" ]];then
#     cat "intermediate/openssl.cnf.example" | sed "s#<CA_default_dir>#$PWD/intermediate#g"  > "intermediate/openssl.cnf"
#     fi
# cat <<EOF
# -------------------- Notes Below --------------------
# Enter pass phrase for ca.key.pem: passphrase
# You are about to be asked to enter information that will be incorporated
# into your certificate request.
# -----
# Country Name (2 letter code) [XX]:CN
# State or Province Name []:Beijing
# Locality Name []:Chaoyang
# Organization Name []:WhateverItIs
# Organizational Unit Name []:School of Computer Science and Cybersecurity
# Common Name []:WhaterverInter CA
# Email Address []:admin@a101e.lab
# -------------------- Notes Above --------------------
# EOF
# # Common Name []:WhaterverInter CA
# openssl req -config intermediate/openssl.cnf -new -sha256 \
#       -key intermediate/private/intermediate.key.pem \
#       -out intermediate/csr/intermediate.csr.pem

# openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
#       -days 3650 -notext -md sha256 \
#       -in intermediate/csr/intermediate.csr.pem \
#       -out intermediate/certs/intermediate.cert.crt

# chmod 444 intermediate/certs/intermediate.cert.crt

# openssl x509 -noout -text \
#       -in intermediate/certs/intermediate.cert.crt

# openssl verify -CAfile certs/ca.cert.crt \
#       intermediate/certs/intermediate.cert.crt

# cat intermediate/certs/intermediate.cert.crt \
#       certs/ca.cert.crt > intermediate/certs/ca-chain.cert.pem

# chmod 444 intermediate/certs/ca-chain.cert.pem
# fi

# 网站证书
domain="whateveritis.cuc.edu.cn" 


if [[ ! -f "intermediate/private/$domain.key.pem" ]];then

openssl genrsa -aes256 \
      -out intermediate/private/$domain.key.pem 2048

openssl rsa -in intermediate/private/$domain.key.pem -out intermediate/private/$domain.key.pem
chmod 400 intermediate/private/$domain.key.pem

if [[ ! -f "intermediate/${domain}.openssl.cnf" ]];then
  cat "intermediate/openssl.cnf.example" | sed "s#<CA_default_dir>#$PWD/intermediate#g"  > "intermediate/openssl.cnf.example.tmp"
  cat "intermediate/openssl.cnf.example.tmp" | sed "s#<DOMAINS>#*.${domain}#g"  > "intermediate/${domain}.openssl.cnf"
  cp "intermediate/${domain}.openssl.cnf" "intermediate/openssl.cnf"
fi

cat <<EOF
-------------------- Notes Below --------------------
Enter pass phrase for ca.key.pem: passphrase
You are about to be asked to enter information that will be incorporated
into your certificate request.
-----
Country Name (2 letter code) [XX]:CN
State or Province Name []:Beijing
Locality Name []:Chaoyang
Organization Name []:WhateverItIs
Organizational Unit Name []:School of Computer Science and Cybersecurity
Common Name []:whateveritis.cuc.edu.cn
Email Address []:admin@a101e.lab
-------------------- Notes Above --------------------
EOF
# Common Name []:Whaterver Server
openssl req -config intermediate/openssl.cnf \
      -key intermediate/private/$domain.key.pem \
      -new -sha256 -out intermediate/csr/$domain.csr.pem

openssl ca -config intermediate/openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in intermediate/csr/$domain.csr.pem \
      -out intermediate/certs/$domain.cert.crt
chmod 444 intermediate/certs/$domain.cert.crt

openssl x509 -noout -text \
      -in intermediate/certs/$domain.cert.crt

openssl verify -CAfile intermediate/certs/ca-chain.cert.pem \
      intermediate/certs/$domain.cert.crt
fi

cat intermediate/certs/$domain.cert.crt intermediate/certs/ca-chain.cert.pem > intermediate/certs/$domain.chained.cert.pem
