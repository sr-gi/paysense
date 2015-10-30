import tools
from bitcoin import *
from requests import post


__author__ = 'sdelgado'


def reputation_transfer(s_key, source_btc_address, destination_btc_address, amount, outside_btc_address=None, outside_amount=None, fee=0, used_txs=None):
    """ Performs a reputation transfer between a source and a destination bitcoin address.

    :param s_key: path to a private a elliptic curve private key
    :type s_key: str
    :param source_btc_address: source bitcoin address, where the bitcoins came from.
    :type source_btc_address: str
    :param destination_btc_address: destination bitcoin address where the bitcoins will be transferred.
    :type destination_btc_address: str
    :param amount: bitcoin amount to be transferred from the source to the destination bitcoin address.
    :type amount: int
    :param used_txs: list of used (but still not verified transactions), it is set to None by default. If a list of transaction is passed, they won't be used to perform the reputation transfer.
    :type used_txs: list
    :param outside_btc_address: bitcoin address where the withdrawal amount of bitcoin will go, it is set to None by default.
    :type outside_btc_address: str
    :param outside_amount: amount of bitcoin that will be withdrawn, it is set to None by default.
    :type outside_amount: int
    :param fee: transaction fee to be paid, it is set to 0 Satoshi by default.
    :type fee: int
    :return: The hash of the created transaction and an updated list of used transactions.
    :rtype: str, list
    """

    # Get both public and private key in their hex representation
    private_key_hex = tools.get_priv_key_hex(s_key)

    # Check the unspent bitcoins from that address
    unspent_transactions = blockr_unspent(source_btc_address, 'testnet')

    # update the used transactions (but still not verified)
    # ToDo Fix this. used_tx should be stored persistently in order to look for them the next time (the program execution could be ended and no reference to it will be found).
    if used_txs is not None:
        for used_tx in used_txs:
            if used_tx in unspent_transactions:
                unspent_transactions.remove(used_tx)
            else:
                used_txs.remove(used_tx)

    else:
        used_txs = []

    necessary_amount, total_btc = tools.get_necessary_amount(unspent_transactions, amount + fee)

    # Build the output of the payment
    if total_btc is not 0:
        # Transfers all the balance except for the transaction fees
        if total_btc == amount + fee:
            outs = [{'value': total_btc - fee, 'address': destination_btc_address}]
        # Transfers an specific amount to the destination address, the remainder (except for the fees) is returned to the source address
        elif outside_btc_address is None or outside_amount is None:
            outs = [{'value': amount, 'address': destination_btc_address}, {'value': total_btc - amount - fee, 'address': source_btc_address}]
        # Transfers an specific amount to a destination address, and the rest (except for the fees) is sent to an outside address
        else:
            outs = [{'value': total_btc - outside_amount, 'address': destination_btc_address}, {'value': outside_amount - fee, 'address': outside_btc_address}]

        # Build the transaction
        tx = mktx(necessary_amount, outs)

        # Sign it
        for i in range(len(necessary_amount)):
            tx = sign(tx, i, private_key_hex)

        code, reason, tx_hash = push_tx(tx)

        if code == '201':
            used_txs.extend(necessary_amount)
    else:
        tx_hash = None

    return tx_hash, used_txs


def tx_info(tx):
    """ Gets the basic information from a given bitcoin transaction of the testnet.

    :param tx: transaction from where the information is requested.
    :type tx: unicode
    :return: A dictionary containing the input address, the output address, the bitcoin amount transferred in the transaction and the number of confirmations.
    :rtype: dict
    """

    input_addresses = []
    output_addresses = []
    payments = []

    response = json.loads(make_request('http://tbtc.blockr.io/api/v1/tx/info/' + tx))
    vins = response.get('data').get('trade').get('vins')
    vouts = response.get('data').get('trade').get('vouts')
    confirmations = response.get('data').get('confirmations')

    for i in range(len(vins)):
        if vins[i].get('address') not in input_addresses:
            input_addresses.append(vins[i].get('address'))
    for i in range(len(vouts)):
        output_addresses.append(vouts[i].get('address'))
        payments.append(vouts[i].get('amount'))

    return {'from': input_addresses, 'to': output_addresses, 'amount': payments, 'confirmations': confirmations}


def history_testnet(btc_address):
    """ Gets the history of transaction from a given bitcoin address from the testnet. This function is analogous to the vbuterin's history function from the bitcointools library
    (used all over the code) but using testnet instead of main bitcoin network

    :param btc_address:  given bitcoin address
    :type btc_address: str
    :return: The history of transaction from the given address, limited to 200 (from the blockr.io api)
    :rtype: list
    """
    history = []
    response = json.loads(make_request('http://tbtc.blockr.io/api/v1/address/txs/' + btc_address))
    if response.get('status') == 'success':
        data = response.get('data')
        txs = data.get('txs')

        for i in range(len(txs)):
            history.append(tx_info(txs[i].get('tx')))

    return history


def push_tx(tx, network='testnet'):
    """ Pushes a transaction to the bitcoin network (the testnet by default) with 0 fees.

    :param tx: transaction to be pushed.
    :type tx: unicode
    :param network: network where the transaction will be pushed.
    :type network: str
    :return: A result consisting on a code (201 if success), a response reason, and the hash of the transaction.
    :rtype: int, str, str
    """
    if network in ['testnet', 'main']:
        if network is 'testnet':
            url = 'https://api.blockcypher.com/v1/btc/test3/txs/push'
        elif network is 'main':
            url = 'https://api.blockcypher.com/v1/btc/main/txs/push'

        data = {'tx': tx}
        response = post(url, data=json.dumps(data))
    else:
        response = 'Bad network'

    r_code = response.status_code
    r_reason = response.reason
    if r_code is 201:
        pushed_tx = json.loads(response.content)
        tx_hash = str(pushed_tx['tx']['hash'])
    else:
        tx_hash = None

    return r_code, r_reason, tx_hash


def get_tx_signature(tx, private_key, btc_address, hashcode=SIGHASH_ALL):
    """  Computes the signature from a given transaction.

    :param tx: input transaction.
    :type tx: unicode
    :param private_key: elliptic curve private key used to sign.
    :type private_key: hex str
    :param btc_address: bitcoin address used as "from" in the transaction (Where the funds came from).
    :type btc_address: str
    :param hashcode: indicates which parts of the transaction will be signed. It is set to all by default

        Possible values:

        - 1 (SIGHASH_ALL)
        - 2 (SIGHASH_NONE)
        - 3 (SIGHASH_SINGLE)

    :type hashcode: int
    :return: The signature of the transaction and the index where it should be placed, or an error and a error code, if there's no transaction to sign.
    :rtype: str, int
    """
    tx_obj = deserialize(tx)
    index = None

    for tx_in in tx_obj['ins']:
        prev_tx_hash = tx_in['outpoint']['hash']
        prev_tx_info = tx_info(prev_tx_hash)
        if btc_address in prev_tx_info['to']:
            index = tx_obj['ins'].index(tx_in)

    if index is not None:
        signing_tx = signature_form(tx, index, mk_pubkey_script(btc_address), hashcode)
        signature = ecdsa_tx_sign(signing_tx, private_key, hashcode)
        response = signature, index
    else:
        response = "Error, no input tx to sign", -1

    return response


def insert_tx_signature(tx, index, signature, public_key):
    """ Inserts a given transaction signature into a given transaction.

    :param tx: input transaction.
    :type tx: unicode
    :param index: input index of the transaction in which the signature must be placed.
    :type index: int
    :param signature: signature to be inserted.
    :type signature: str
    :param public_key: elliptic curve public key used to insert the signature in the corresponding input.
    :type public_key: hex str
    :return: The transaction with the signature inserted.
    :rtype: unicode
    """
    tx_obj = deserialize(tx)
    tx_obj["ins"][index]["script"] = serialize_script([signature, public_key])

    return serialize(tx_obj)


