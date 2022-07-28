from Generatekeys import generate_key
from CreateCSR import generate_csr
from CreateCRT import generate_crt
import openssl
from OpenSSL import crypto
from OpenSSL import SSL
path=r'./ca/'
CN=u"WhateverCA"
issuer=u"WhateverCA"
key1=generate_key(path)
issuerkey=key1
generate_crt(issuerkey,key1,path,issuer,CN)

path=r'./mid/'
issuer=u"WhateverCA"
CN=u"WhateverMID"
key2=generate_key(path)
generate_crt(issuerkey,key2,path,issuer,CN)

path=r'./leaf/'
issuer=u"WhateverMID"
CN=u"WhateverLEAF"
key3=generate_key(path)
issuerkey=key2
generate_crt(issuerkey,key3,path,issuer,CN)

