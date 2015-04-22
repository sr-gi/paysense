__author__ = 'sdelgado'

import requests
from pycoin import ecdsa
from flask import json
from base64 import b64encode

f = open('private_key.pem', 'r')
secret_exponent = int(f.read(), 16)
f.close()

message = 34512343291048
signature = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, message)
bitcoin_address = "1Dn9CJJgt8fqzTdDiPvcRiA5cmnPNkx3Wx"

data = {'message': message, 'signature': signature, 'bitcoin_address': bitcoin_address}
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)

assert r.status_code == 200
assert r.reason == 'OK'
assert r.content == 'Sensing data correctly verified'

f = open(bitcoin_address + '.pem', 'r')
cs_pem_data = b64encode(f.read())
f.close()
data['cs_pem_data'] = cs_pem_data
r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)

assert r.status_code == 200
assert r.reason == 'OK'
assert r.content == 'Sensing data correctly verified'
