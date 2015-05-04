__author__ = 'sdelgado'

import hashlib
from base58 import b58encode

addrtype = 0


def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()


def hash_160_to_bc_address(h160, v=None):
    if v is None:
        v = addrtype
    vh160 = chr(v) + h160
    h = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()
    addr = vh160 + h[0:4]
    return b58encode(addr)


def public_key_to_bc_address(public_key, v=None):
    if v is None:
        v = addrtype
    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, v)
