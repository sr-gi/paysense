__author__ = 'sdelgado'
from bitcointools import *
from bitcoin import *

# Performs a bitcoin transaction from a single user (inputs to be signed just by one private key)
# @s_key is the OpenSSl private key object representing the elliptic curve private key
# @source_bc_address is the CS own bitcoin address, where the bitcoins came from
# @destination_bc_address is the bitcoin address of the new CS pseudonym, where the bitcoins will be transferred
# @amount is the bitcoin amount to be transferred from the source to the destination bitcoin addresses
# @outside_bc_address is the bitcoin address where the withdrawal amount of bitcoin will go
# @outside_amount is the amount of bitcoin that will be withdrawn
# @fee represent the transaction fee, it is set to 0 Satoshi by default
# @return an updated list of the used transactions
def single_payment(s_key, source_bc_address, destination_bc_address, amount, used_txs=None, outside_bc_address=None, outside_amount=None, fee=0):

    # Get both public and private key in their hex representation
    private_key_hex = get_priv_key_hex(s_key)

    # Check the unspent bitcoins from that address
    unspent_transactions = blockr_unspent(source_bc_address, 'testnet')

    # update the used transactions (but still not verified)
    if used_txs is not None:
        for used_tx in used_txs:
            if used_tx in unspent_transactions:
                unspent_transactions.remove(used_tx)
            else:
                used_txs.remove(used_tx)

    else:
        used_txs = []

    necessary_amount, total_bitcoins = get_necessary_amount(unspent_transactions, amount)

    # Build the output of the payment
    if total_bitcoins is not 0:
        # Transfers all the balance except for the transaction fees
        if total_bitcoins == amount:
            outs = [{'value': total_bitcoins - fee, 'address': destination_bc_address}]
        # Transfers an specific amount to the destination address, the remainder (except for the fees) is returned to the source address
        elif outside_bc_address is None or outside_amount is None:
            outs = [{'value': amount, 'address': destination_bc_address}, {'value': total_bitcoins - amount - fee, 'address': source_bc_address}]
        # Transfers an specific amount to a destination address, and the rest (except for the fees) is sent to an outside address
        else:
            outs = [{'value': total_bitcoins - outside_amount, 'address': destination_bc_address}, {'value': outside_amount - fee, 'address': outside_bc_address}]

        # Build the transaction
        tx = mktx(necessary_amount, outs)

        # Sign it
        for i in range(len(necessary_amount)):
            tx = sign(tx, i, private_key_hex)

        print tx
        exit(0)

        code, reason, tx_hash = push_tx(tx)

        if code == '201':
            used_txs.extend(necessary_amount)

        print code, reason, tx_hash

    return used_txs


