__author__ = 'sdelgado'

from base64 import b64encode, b64decode
import urllib2

import requests
from flask import json
from M2Crypto import EC, BIO, EVP
from bitcointools import private_key_to_wif
from base58 import b58encode
from binascii import *


bitcoin_address = "mtSLzvNAZnrpyGW1UBkmb3ovap8myuMJrZ"
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
    #private_key_to_wif("60E208D4FA2006500049665A52A8CD0EB77127509274A2FFD659FD15A989D0B4")
    print b58encode(a2b_hex("6f5f329a9ff1141d2ae6f1a6cbbd55b457b7324430d676b25a"))
    ec_pub = EC.load_pub_key("paysense_public.key")
    signature2 = ec.sign_dsa_asn1(message)
    print ec_pub.verify_dsa_asn1(message, signature2)
    
    #print b2a_hex(ec_pub.get_der())

def main():
    #test1()
    #test2()
    #test3()
    #test4()
    #test5()
    test6()

if __name__ == '__main__':
    main()
