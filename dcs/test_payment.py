__author__ = 'sdelgado'
from M2Crypto import EC, BIO, EVP
from bitcointools import public_key_to_bc_address, get_pub_key_hex
from pybitcointools import *
from binascii import b2a_hex
from asn1tinydecoder import asn1_node_root, asn1_get_value, asn1_node_first_child, asn1_node_next, asn1_get_all
from base64 import b64decode

def main():
    PK = EC.load_pub_key('dcs_paysense_public.key')
    SK = EC.load_key('dcs_paysense.key')

    # Generate a Pkey object to store the EC keys
    der = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE+MuApoYAlKnq41ww01T5CXDoVvD058Vxc/LOIsL6S74fQzT3dNdS0yyqEY9lSq+1ahMDpsnuaN9+sBYTBq+QDA=="
    der = base64.b64decode(der)
    root = asn1_node_root(der)
    print b2a_hex(root)
    key = b2a_hex(asn1_get_all(der, root))

    print key

    exit(0)

    private_key_hex = 'f4e9de1396b615b2e1a6439fc6311ce191caaa69f395fcb5abf42c2166e6022c'
    public_key_hex = get_pub_key_hex(PK)

    assert (privtopub(private_key_hex) == public_key_hex)

    bitcoin_address = public_key_to_bc_address(public_key_hex, 'test')
    unspent_bitcoins = blockr_unspent(bitcoin_address, 'testnet')

    total_bitcoins = unspent_bitcoins[0].get('value')

    cs_bt_address = 'mpFECAZYV4dXnK2waQC36AoZsAftv5RAkM'
    outs = [{'value': total_bitcoins - 1000, 'address': cs_bt_address}]

    tx = mktx(unspent_bitcoins, outs)
    signed_tx = sign(tx, 0, private_key_hex)

    result = blockr_pushtx(signed_tx, 'testnet')

    print result.get('status')


if __name__ == '__main__':
    main()