from littleRedCUC.SystemSK import generate_K
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import csv
import os
from pathlib import Path

# RSA
key=generate_K()
system_path = Path('./instance') / 'system'
if not Path('./instance').exists():
    Path('./instance').mkdir()
if not system_path.exists():
    system_path.mkdir()
pathSK='SystemSK.pem'
pathPK='SystemPK.pem'
# private_key = ed25519.Ed25519PrivateKey.generate()
# private_bytes = private_key.private_bytes(
#     encoding=serialization.Encoding.Raw,
#     format=serialization.PrivateFormat.Raw,
#     encryption_algorithm=serialization.NoEncryption()
# )

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

with open(pathSK, "wb") as f:
    f.write(private_key.private_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PrivateFormat.PKCS8,
   encryption_algorithm=serialization.BestAvailableEncryption(b'adminadmin')
        ))

# with open("path/to/key.pem", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#     )

# public_key = private_key.public_key()
# public_bytes = public_key.public_bytes(
#     encoding=serialization.Encoding.Raw,
#     format=serialization.PublicFormat.Raw
# )

public_key = private_key.public_key()
with open(pathPK, "wb") as f:
    f.write(public_key.public_bytes(
         encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

# loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

# 对私钥进行对称加密

# 路径存在csv文件里
headers=['PK','SK']
data = [pathPK, pathSK]
with open('instance/system/System.csv', mode='a', newline='', encoding='utf-8-sig') as f:
    csv_writer = csv.writer(f, delimiter=',')
    if not os.path.getsize('instance/system/System.csv'):    
        csv_writer.writerow(headers)
    csv_writer.writerow(data)