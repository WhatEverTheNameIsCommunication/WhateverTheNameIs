# 参考 https://cryptography.io/en/latest/x509/tutorial/

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Generatekeys import generate_key
import datetime

def generate_csr(key,path,CN):
    # Generate key
    # key=generate_key(path)

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Chaoyang"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Whatever"),
        # x509.NameAttribute(NameOID.COMMON_NAME, u"WhateverItIs.cuc.edu.cn"),
        x509.NameAttribute(NameOID.COMMON_NAME, CN),
    ])).add_extension(
        x509.SubjectAlternativeName([
            # 证书可用于的子站点域名列表
            x509.DNSName(u"WhateverItIs.cuc.edu.cn"),
        ]),
        critical=False,
    # Sign the CSR with our private key.
    ).sign(key, hashes.SHA256(),default_backend)
    # Write our CSR out to disk.
    path=path+'csr.csr'
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

