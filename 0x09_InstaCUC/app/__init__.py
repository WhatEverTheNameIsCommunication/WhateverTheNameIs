from .application import create_app
from passlib.totp import TOTP, generate_secret


TotpFactory = TOTP.using(issuer="WhateverItIs.cuc.edu.cn", secrets={"1": generate_secret()})

app = create_app()