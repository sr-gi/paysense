__author__ = 'sdelgado'

from base58 import b58encode
from binascii import a2b_hex, b2a_hex
from asn1tinydecoder import *
from subprocess import check_output, STDOUT
from bitcoin import *
from flask import json
from M2Crypto import X509

PUBKEY_HASH = 0
TESTNET_PUBKEY_HASH = 111
WIF = 128
TESTNET_WIF = 239

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

    # If the key starts with 00, the two first characters are removed
    if raw_key[:2] == '00':
        private_key_hex = raw_key[2:]
    else:
        private_key_hex = raw_key

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

def bc_address_from_cert(certificate):
    certificate = X509.load_cert(certificate)
    details = certificate.get_subject().as_text()
    bc_address = details[details.find('CN') + 3:]

    return bc_address

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

def insert_signature(tx, index, signature, public_key_hex):

    tx_obj = deserialize(tx)
    tx_obj["ins"][index]["script"] = serialize_script([signature, public_key_hex])

    return serialize(tx_obj)

def get_tx_signature(tx, private_key_hex, bc_address, hashcode=SIGHASH_ALL):

    tx_obj = deserialize(tx)
    index = None

    for tx_in in tx_obj['ins']:
        prev_tx_hash = tx_in['outpoint']['hash']
        prev_tx_info = tx_info(prev_tx_hash)
        if bc_address in prev_tx_info['to']:
            index = tx_obj['ins'].index(tx_in)

    if index is not None:
        signing_tx = signature_form(tx, index, mk_pubkey_script(bc_address), hashcode)
        signature = ecdsa_tx_sign(signing_tx, private_key_hex, hashcode)
        response = signature, index
    else:
        response = "Error, no input tx to sign"

    return response

