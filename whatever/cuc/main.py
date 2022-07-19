from littleRedCUC import create_app
# from passlib.totp import TOTP, generate_secret

# TotpFactory = TOTP.using(issuer="WhateverItIs.cuc.edu.cn", secrets={"1": generate_secret()})
app = create_app()

if __name__ == '__main__':
    app.run(debug=True,ssl_context=("./x.509/intermediate/certs/whateveritis.cuc.edu.cn.cert.crt", './x.509/intermediate/private/whateveritis.cuc.edu.cn.key.pem'))