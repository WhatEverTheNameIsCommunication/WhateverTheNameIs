from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Generatekeys import generate_key
import datetime

path='./self-signed/'
key=generate_key(path)


subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chaoyang"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Whatever"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"WhateverItIs.cuc.edu.cn"),
])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # Our certificate will be valid for 10 years
    datetime.datetime.utcnow() + datetime.timedelta(days=10*365)
).add_extension(
    x509.SubjectAlternativeName([
    # 证书可用于的子站点域名列表
    x509.DNSName(u"WhateverItIs.cuc.edu.cn"),
	]),
    critical=False,
# Sign our certificate with our private key
).sign(key, hashes.SHA256(),default_backend)
# Write our certificate out to disk.
with open("./self-signed/self-signed-key.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# 用于flask https
# from flask import Flask    
# app = Flask(__name__)    
# app.run('0.0.0.0', debug=True, port=8100, ssl_context=("./self-signed/self-signed-key.pem", './self-signed/key.pem'))  
# 运行后
# Enter PEM pass phrase:
# passphrase