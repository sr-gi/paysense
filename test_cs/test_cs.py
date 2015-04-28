__author__ = 'sdelgado'

import requests
from flask import json
from base64 import b64encode
from M2Crypto import EC
import urllib2

bitcoin_address = "1Dn9CJJgt8fqzTdDiPvcRiA5cmnPNkx3Wx"
ec = EC.load_key('private_key.pem')

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
    f = open(bitcoin_address + '.pem', 'r')
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
    response = urllib2.urlopen('http://127.0.0.1:5001/sign_in?bitcoin_address=' + bitcoin_address)
    data = json.load(response)
    public_key = data["public_key"]
    private_key = data["private_key"]
    certificate = data["certificate"]

    f = open('public_key.pem', 'w')
    f.write(public_key)
    f.close()
    f = open('private_key.pem', 'w')
    f.write(private_key)
    f.close()
    f = open(bitcoin_address + '.pem', 'w')
    f.write(certificate)
    f.close()


def main():
    test1()
    test2()
    test3()
    test4()
    #test5()

if __name__ == '__main__':
    main()
