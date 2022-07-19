from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os
# Generate our key
def generate_key(path):
    if path==None:
        path='./'
    dir = os.path.join(path) 
    print(dir) 

    if not os.path.exists(dir):
        os.makedirs(dir, mode=0o755)

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    
    path=dir+'key.pem'
    print(path) 
    
    # Write our key to disk for safe keeping
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    return key