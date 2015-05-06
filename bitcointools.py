__author__ = 'sdelgado'

import hashlib
from base58 import b58encode
from binascii import a2b_hex, b2a_hex
from asn1tinydecoder import *

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


def public_key_to_bc_address(public_key, v=None):
    if v is 'test':
        v = TESTNET_PUBKEY_HASH
    else:
        v = PUBKEY_HASH
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, v)


def get_pub_key_hex(public_key):
    der = public_key.get_der()
    root = asn1_node_root(der)
    key = b2a_hex(asn1_get_value(der, asn1_node_next(der, asn1_node_first_child(der, root))))
    return key[2:]


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


