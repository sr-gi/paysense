__author__ = 'sdelgado'
from M2Crypto import EC
from bitcointools import public_key_to_bc_address, get_pub_key_hex, get_priv_key_hex
from pybitcointools import *

PK_FILE = 'dcs_paysense_public.key'
SK_FILE = 'dcs_paysense.key'

def main():
    public_key = EC.load_pub_key(PK_FILE)

    private_key_hex = get_priv_key_hex(SK_FILE)
    public_key_hex = get_pub_key_hex(public_key)

    assert (privtopub(private_key_hex) == public_key_hex)

    bitcoin_address = public_key_to_bc_address(public_key_hex, 'test')
    unspent_bitcoins = blockr_unspent(bitcoin_address, 'testnet')

    print unspent_bitcoins

    total_bitcoins = unspent_bitcoins[0].get('value')

    cs_bt_address = 'mpFECAZYV4dXnK2waQC36AoZsAftv5RAkM'
    outs = [{'value': total_bitcoins - 1000, 'address': cs_bt_address}]

    tx = mktx(unspent_bitcoins, outs)
    signed_tx = sign(tx, 0, private_key_hex)

    print signed_tx

    exit(0)

    result = blockr_pushtx(signed_tx, 'testnet')

    print result.get('status')


if __name__ == '__main__':
    main()