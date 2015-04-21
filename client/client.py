__author__ = 'sdelgado'

import requests
from pycoin import ecdsa
from flask import json

f = open('private_key.pem', 'r')
secret_exponent = int(f.read(), 16)

message = 34512343291048
signature = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, message)
bitcoin_address = "1Dn9CJJgt8fqzTdDiPvcRiA5cmnPNkx3Wx"

data = {'message': message, 'signature': signature, 'bitcoin_address': bitcoin_address}
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)
print r.status_code, r.reason