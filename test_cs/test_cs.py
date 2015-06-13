__author__ = 'sdelgado'

from base64 import b64encode
import urllib2

import requests
from bitcointools import *
from bitcointransactions import single_payment
from flask import json
from M2Crypto import EC
from bitcoin import blockr_unspent
from random import randint

P_KEY = 'paysense_public.key'
S_KEY = 'paysense.key'
CERT = 'paysense.crt'

TRANSACTION_CS = 'crowdSensors/transactionTest/'
REPUTATION_CS = 'crowdSensors/reputationTest/'

CS1_PATH = 'cs1/'
CS2_PATH = 'cs2/'

CHOSEN_CS = REPUTATION_CS + CS2_PATH
bitcoin_address = bc_address_from_cert(CHOSEN_CS + CERT)


def init_parameters():
    ec = EC.load_key(CHOSEN_CS + S_KEY)

    message = '34512343291048'
    signature = ec.sign_dsa_asn1(message)
    signature = b64encode(signature)

    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    data = {'message': message, 'signature': signature, 'bitcoin_address': bitcoin_address}

    return headers, data


# Request without certificate
def test1():
    headers, data = init_parameters()

    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)

    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == 'Sensing data correctly verified'


# Request with certificate
def test2():
    headers, data = init_parameters()

    f = open(CHOSEN_CS + CERT, 'r')
    cs_pem_data = b64encode(f.read())
    f.close()
    data['cs_pem_data'] = cs_pem_data
    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)
    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == 'Sensing data correctly verified'


# Request with wrong signature (without certificate)
def test3():
    headers, data = init_parameters()

    ec = EC.load_key(CHOSEN_CS + S_KEY)
    message = '34512343291049'
    signature = ec.sign_dsa_asn1(message)
    signature = b64encode(signature)
    data['signature'] = signature

    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)
    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == "Sensing data can't be verified"


# Request with wrong signature (with certificate)
def test4():
    headers, data = init_parameters()

    f = open(CHOSEN_CS + CERT, 'r')
    cs_pem_data = b64encode(f.read())
    f.close()
    data['cs_pem_data'] = cs_pem_data

    ec = EC.load_key(CHOSEN_CS + S_KEY)
    message = '34512343291049'
    signature = ec.sign_dsa_asn1(message)
    signature = b64encode(signature)
    data['signature'] = signature

    r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)
    assert r.status_code == 200
    assert r.reason == 'OK'
    assert r.content == "Sensing data can't be verified"


# Register test
def test5():
    response = urllib2.urlopen('http://127.0.0.1:5001/sign_in?bitcoin_address=')
    data = json.load(response)
    public_key = data["public_key"]
    private_key = data["private_key"]
    certificate = data["certificate"]

    f = open(P_KEY, 'w')
    f.write(public_key)
    f.close()
    f = open(S_KEY, 'w')
    f.write(private_key)
    f.close()
    f = open(CERT, 'w')
    f.write(certificate)
    f.close()


# Import formats test
def test6():
    ec = EC.load_key(CHOSEN_CS + S_KEY)
    # Generate the bitcoin address from the public key
    public_key_hex = get_pub_key_hex(ec.pub())
    bitcoin_address = public_key_to_bc_address(public_key_hex, 'test')
    print bitcoin_address

    # Generate WIF from private key
    private_key_hex = get_priv_key_hex(CHOSEN_CS + S_KEY)
    print private_key_hex
    private_key_wif = private_key_to_wif(private_key_hex, 'test')
    print private_key_wif


# This test emulates the CS reputation exchange when he doesn't trust any other CS nor the ACA
def self_reputation_exchange(new_bc_address):

    unspent_transactions = blockr_unspent(bitcoin_address, 'testnet')
    unspent_bitcoins = 0
    for transaction in unspent_transactions:
        unspent_bitcoins += transaction.get('value')

    # ToDo: Perform a proper way to withdraw reputation
    reputation_withdraw = (float(randint(2, 5)) / 100) * unspent_bitcoins

    print unspent_bitcoins, reputation_withdraw

    outside_address = bc_address_from_cert(TRANSACTION_CS + CS1_PATH + CERT)

    single_payment(CHOSEN_CS + S_KEY, bitcoin_address, new_bc_address, unspent_bitcoins,
                   outside_address, int(reputation_withdraw))

    response = urllib2.urlopen('http://127.0.0.1:5001/reputation_exchange?new_bc_address=' + new_bc_address)

    assert json.load(response).get('verified')


def cs_reputation_exchange(partner_new_bc_address, outside_bc_address):
    # ToDo: A proper way to find the pair for the exchange in a anonymous way should be found or developed
    unspent_transactions = blockr_unspent(bitcoin_address, 'testnet')
    unspent_bitcoins = 0
    for transaction in unspent_transactions:
        unspent_bitcoins += transaction.get('value')

    # ToDo: Perform a proper way to withdraw reputation
    reputation_withdraw = (float(randint(2, 5)) / 100) * unspent_bitcoins

    single_payment(CHOSEN_CS + S_KEY, bitcoin_address, partner_new_bc_address, unspent_bitcoins,
                   outside_bc_address, int(reputation_withdraw))


def main():
    # test1()
    # test2()
    # test3()
    # test4()
    # test5()
    # test6()
    self_reputation_exchange(bc_address_from_cert(TRANSACTION_CS + CS2_PATH + CERT))

    # cs_reputation_exchange(bc_address_from_cert(REPUTATION_CS + CS2_PATH + CERT), bc_address_from_cert(TRANSACTION_CS + CS2_PATH + CERT))


if __name__ == '__main__':
    main()
