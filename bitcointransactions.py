__author__ = 'sdelgado'
from M2Crypto import EC
from bitcointools import *
from bitcoin import *

# Performs a bitcoin transaction from a single user (inputs to be signed just by one private key)
# @s_key is the OpenSSl private key object representing the elliptic curve private key
# @source_bc_address is the CS own bitcoin address, where the bitcoins came from
# @destination_bc_address is the bitcoin address of the new CS pseudonym, where the bitcoins will be transferred
# @amount is the bitcoin amount to be transferred from the source to the destination bitcoin addresses
# @outside_bc_address is the bitcoin address where the withdrawal amount of bitcoin will go
# @outside_amount is the amount of bitcoin that will be withdrawn
# @fee represent the transaction fee, it is set to 1000 Satoshi by default
def single_payment(s_key, source_bc_address, destination_bc_address, amount, outside_bc_address, outside_amount, fee=None):
    # Set the default fee
    if fee is None:
        fee = 1000

    # Get both public and private key in their hex representation
    private_key_hex = get_priv_key_hex(s_key)

    # Check the unspent bitcoins from that address
    unspent_bitcoins = blockr_unspent(source_bc_address, 'testnet')

    # Build the output of the payment
    outs = [{'value': amount - outside_amount - fee, 'address': destination_bc_address}, {'value': outside_amount, 'address': outside_bc_address}]

    # Build the transaction
    tx = mktx(unspent_bitcoins, outs)

    # Sign it
    signed_tx = sign(tx, 0, private_key_hex)

    result = blockr_pushtx(signed_tx, 'testnet')

    print result

# Performs a bitcoin transaction from a multiple users (inputs to be signed by more than one private key)
# ToDo: CHANGE THIS FUNCTION
# Currently is mostly hardcoded, maybe it will be deleted. If it's not, it will be improved.
def multi_payment(cs1_p_key, cs1_s_key, cs2_p_key, cs2_s_key, cs_bitcoin_address, amount, fee=None):
    if fee is None:
        fee = 1000

    # Load both public keys
    public_key = EC.load_pub_key(cs1_p_key)
    public_key_2 = EC.load_pub_key(cs2_p_key)

    # Get the hex representation of the keys from both the DCS and the CS2
    private_key_hex = get_priv_key_hex(cs1_s_key)
    public_key_hex = get_pub_key_hex(public_key)

    private_key_2_hex = get_priv_key_hex(cs2_s_key)
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