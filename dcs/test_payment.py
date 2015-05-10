__author__ = 'sdelgado'
from M2Crypto import EC
from bitcointools import *
from pybitcointools import *

PK_FILE = 'dcs_paysense_public.key'
SK_FILE = 'dcs_paysense.key'
CS_BC_ADDRESS = 'mpFECAZYV4dXnK2waQC36AoZsAftv5RAkM'
CS2_BC_ADDRESS = 'mkhrXULTeuwdNGSKVKhR1tjCFMktT6pXFX'

def single_payment(cs_bitcoin_address):
    public_key = EC.load_pub_key(PK_FILE)

    private_key_hex = get_priv_key_hex(SK_FILE)
    public_key_hex = get_pub_key_hex(public_key)

    assert (privtopub(private_key_hex) == public_key_hex)

    bitcoin_address = public_key_to_bc_address(public_key_hex, 'test')
    unspent_bitcoins = blockr_unspent(bitcoin_address, 'testnet')

    total_bitcoins = unspent_bitcoins[0].get('value')

    print 'Total DCS Bitcoins ' + str(total_bitcoins)

    outs = [{'value': total_bitcoins - 1000, 'address': cs_bitcoin_address}]

    print 'CS History ' + str(history)

    tx = mktx(unspent_bitcoins, outs)
    signed_tx = sign(tx, 0, private_key_hex)

    exit(0)

    result = blockr_pushtx(signed_tx, 'testnet')

    print result.get('status')


def main():
    history_cs = history_testnet(CS_BC_ADDRESS)
    print 'History CS ' + str(history_cs)
    history_cs2 = history_testnet(CS2_BC_ADDRESS)
    print 'History CS2 ' + str(history_cs2)
    history_dcs = history_testnet('mqcKJjxaaUcG37MFA3jvyDkaznWs4kyLyg')
    print 'History DCS ' + str(history_dcs)

if __name__ == '__main__':
    main()