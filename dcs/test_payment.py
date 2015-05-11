__author__ = 'sdelgado'
from M2Crypto import EC
from bitcointools import *
from bitcoin import *

PK_FILE = 'dcs_paysense_public.key'
SK_FILE = 'dcs_paysense.key'
CS_BC_ADDRESS = 'mpFECAZYV4dXnK2waQC36AoZsAftv5RAkM'
CS2_BC_ADDRESS = 'mkhrXULTeuwdNGSKVKhR1tjCFMktT6pXFX'


def histories():
    history_cs = history_testnet(CS_BC_ADDRESS)
    print 'History CS ' + str(history_cs)
    history_cs2 = history_testnet(CS2_BC_ADDRESS)
    print 'History CS2 ' + str(history_cs2)
    history_dcs = history_testnet('mqcKJjxaaUcG37MFA3jvyDkaznWs4kyLyg')
    print 'History DCS ' + str(history_dcs)

def single_payment(cs_bitcoin_address, amount, fee=None):
    # Set the default fee
    if fee is None:
        fee = 1000

    # Load the public key from the key file
    public_key = EC.load_pub_key(PK_FILE)

    # Get both public and private key in their hex representation
    private_key_hex = get_priv_key_hex(SK_FILE)
    public_key_hex = get_pub_key_hex(public_key)

    # Get the bitcoin address from the public key
    bitcoin_address = public_key_to_bc_address(public_key_hex, 'test')

    # Check the unspent bitcoins from that address
    unspent_bitcoins = blockr_unspent(bitcoin_address, 'testnet')

    # Parse the total unspent bitcoins
    total_bitcoins = unspent_bitcoins[0].get('value')

    print 'Total DCS Bitcoins ' + str(total_bitcoins)

    # Build the output of the payment
    outs = [{'value': amount, 'address': cs_bitcoin_address}, {'value': total_bitcoins - amount - fee, 'address': bitcoin_address}]

    # Build the transaction
    tx = mktx(unspent_bitcoins, outs)

    # Sign it
    signed_tx = sign(tx, 0, private_key_hex)

    result = blockr_pushtx(signed_tx, 'testnet')

    print result


def multi_payment(cs_bitcoin_address, amount, fee=None):
    if fee is None:
        fee = 1000

    # Load both public keys
    public_key = EC.load_pub_key(PK_FILE)
    public_key_2 = EC.load_pub_key('../test_cs/paysense_2_public.key')

    # Get the hex representation of the keys from both the DCS and the CS2
    private_key_hex = get_priv_key_hex(SK_FILE)
    public_key_hex = get_pub_key_hex(public_key)

    private_key_2_hex = get_priv_key_hex('../test_cs/paysense_2.key')
    public_key_2_hex = get_pub_key_hex(public_key_2)


    # Get their bitcoin addresses and their unspent bitcoins
    bitcoin_address = public_key_to_bc_address(public_key_hex, 'test')
    unspent_bitcoins = blockr_unspent(bitcoin_address, 'testnet')

    bitcoin_address_2 = public_key_to_bc_address(public_key_2_hex, 'test')
    unspent_bitcoins_2 = blockr_unspent(bitcoin_address_2, 'testnet')

    # Parse total bitcoin for both
    total_bitcoins = unspent_bitcoins[0].get('value')
    total_bitcoins_2 = unspent_bitcoins_2[0].get('value')

    # Build the output dividing both the amount to pay and the taxes to both addresses
    outs = [{'value': amount, 'address': cs_bitcoin_address}, {'value': total_bitcoins - amount / 2 - fee / 2, 'address': bitcoin_address}, {'value': total_bitcoins_2 - amount / 2 - fee / 2, 'address': bitcoin_address_2}]

    # Build the transaction
    tx = mktx(unspent_bitcoins, unspent_bitcoins_2, outs)

    # Sign it
    # ToDo: build a loop to do it automatically, in this case DCS had one source funds and CS2 had 2.
    signed_tx = sign(tx, 0, private_key_hex)
    signed_tx = sign(signed_tx, 1, private_key_2_hex)
    signed_tx = sign(signed_tx, 2, private_key_2_hex)

    print signed_tx

    result = blockr_pushtx(signed_tx, 'testnet')

    print result

def main():
    single_payment(CS2_BC_ADDRESS, 10000)
    #multi_payment(CS_BC_ADDRESS, 2000)

if __name__ == '__main__':
    main()