__author__ = 'sdelgado'

from base64 import b64encode
import urllib2

import requests, bitcointools
from flask import json
from M2Crypto import EC
from pycoin import tx


bitcoin_address = "mpFECAZYV4dXnK2waQC36AoZsAftv5RAkM"
ec = EC.load_key('paysense.key')

message = '34512343291048'
signature = ec.sign_dsa_asn1(message)
signature = b64encode(signature)

headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
data = {'message': message, 'signature': signature, 'bitcoin_address': bitcoin_address}


def test1():
    # Request without certificate
    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)

    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == 'Sensing data correctly verified'


def test2():
    # Request with certificate
    f = open('paysense.crt', 'r')
    cs_pem_data = b64encode(f.read())
    f.close()
    data['cs_pem_data'] = cs_pem_data
    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)
    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == 'Sensing data correctly verified'


def test3():
    # Request with wrong signature (with certificate)
    message = '34512343291049'
    signature = ec.sign_dsa_asn1(message)
    signature = b64encode(signature)
    data['signature'] = signature
    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)
    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == "Sensing data can't be verified"


def test4():
    # Request with wrong signature (without certificate)
    del data['cs_pem_data']
    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)
    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == "Sensing data can't be verified"


def test5():
    response = urllib2.urlopen('http://127.0.0.1:5001/sign_in?bitcoin_address=')
    data = json.load(response)
    public_key = data["public_key"]
    private_key = data["private_key"]
    certificate = data["certificate"]

    f = open('paysense_public.key', 'w')
    f.write(public_key)
    f.close()
    f = open('paysense.key', 'w')
    f.write(private_key)
    f.close()
    f = open('paysense.crt', 'w')
    f.write(certificate)
    f.close()


def test6():
    # Generate the bitcoin address from the public key
    public_key_hex = bitcointools.get_pub_key_hex(ec.pub())
    bitcoin_address = bitcointools.public_key_to_bc_address(public_key_hex, 'test')
    print bitcoin_address

    # Generate WIF from private key
    private_key_wif = bitcointools.private_key_to_wif("a132c58610842880c13958ad7f24dbaecdd555e9c577abd8b7e758c4d972b32b", 'test')
    print private_key_wif


def main():
    test1()
    test2()
    test3()
    test4()
    #test5()
    #test6()

if __name__ == '__main__':
    main()
