__author__ = 'sdelgado'

import hashlib
from base58 import b58encode
from binascii import a2b_hex, b2a_hex
from asn1tinydecoder import *
from subprocess import check_output, STDOUT
from pybitcointools import make_request, blockr_fetchtx, deserialize, script_to_address, scriptaddr
from flask import json


PUBKEY_HASH = 0
TESTNET_PUBKEY_HASH = 111
WIF = 128
TESTNET_WIF = 239
DCS_BC_ADDRESS = 'mqcKJjxaaUcG37MFA3jvyDkaznWs4kyLyg'


def hash_160(public_key):
    md = hashlib.new('ripemd160')
    sha256 = hashlib.sha256(a2b_hex(public_key)).digest()
    md.update(sha256)
    return md.digest()


def hash_160_to_bc_address(h160, v):
    vh160 = chr(v) + h160
    h = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()
    addr = vh160 + h[0:4]
    return b58encode(addr)


def get_pub_key_hex(public_key):
    der = public_key.get_der()
    root = asn1_node_root(der)
    key = b2a_hex(asn1_get_value(der, asn1_node_next(der, asn1_node_first_child(der, root))))
    return key[2:]

# ToDO: Find a way to get the SK without a system call
def get_priv_key_hex(pk_file_path):

    cmd = ['openssl', 'ec', '-in', pk_file_path, '-text', '-noout']
    response = check_output(cmd, stderr=STDOUT)

    raw_key = response[response.find('priv:') + 8: response.find('pub:')]
    raw_key = raw_key.replace(":", "")
    raw_key = raw_key.replace(" ", "")
    raw_key = raw_key.replace("\n", "")
    # ToDO: Ensure that the first two values of the SK are always 00
    private_key_hex = raw_key[2:]

    return private_key_hex

def public_key_to_bc_address(public_key, v=None):
    if v is 'test':
        v = TESTNET_PUBKEY_HASH
    else:
        v = PUBKEY_HASH
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, v)

def private_key_to_wif(private_key, v=None):
    if v is 'test':
        v = TESTNET_WIF
    else:
        v = WIF

    e_pkey = chr(v) + a2b_hex(private_key)
    sha256_1 = hashlib.sha256(e_pkey).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    checksum = sha256_2[0:4]
    wif = e_pkey + checksum
    wif = b58encode(wif)
    return wif

def check_payers(history):
    validation = True
    for i in range(len(history)):
        payer = history[i].get('from')
        if payer is not DCS_BC_ADDRESS:
            validation = False

    return validation

def tx_info(tx):
    input_addresses = []
    output_addresses = []
    payments = []

    response = json.loads(make_request('http://tbtc.blockr.io/api/v1/tx/info/' + tx))
    vins = response.get('data').get('trade').get('vins')
    vouts = response.get('data').get('trade').get('vouts')

    for i in range(len(vins)):
        input_addresses.append(vins[i].get('address'))
    for i in range(len(vouts)):
        output_addresses.append(vouts[i].get('address'))
        payments.append(vouts[i].get('amount'))

    return {'from': input_addresses, 'to': output_addresses, 'amount': payments}

def history_testnet(bitcoin_address):
    history = []
    response = json.loads(make_request('http://tbtc.blockr.io/api/v1/address/txs/' + bitcoin_address))
    if response.get('status') == 'success':
        data = response.get('data')
        txs = data.get('txs')

        for i in range(len(txs)):
            history.append(tx_info(txs[i].get('tx')))

    return history

