from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

import tools
from bitcoin import *
from requests import post
from utils.certificate.tools import check_certificate


__author__ = 'sdelgado'


def reputation_transfer(s_key, source_btc_address, destination_btc_address, amount, outside_btc_address=None, outside_amount=None, fee=0, used_txs=None):
    """ Performs a reputation transfer between a source and a destination bitcoin address.

    :param s_key: path to a private a elliptic curve private key.
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

    necessary_amount, total_btc = tools.get_necessary_amount(unspent_transactions, amount + fee, 'small')

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

        if fee is not 0:
            # ToDo: Change this once the problems with the blockr API has been solved
            code, reason, tx_hash = push_tx(tx, fee=True)
            # tx_hash = local_push(tx)
        else:
            code, reason, tx_hash = push_tx(tx)

        if code in [200, 201]:
            used_txs.extend(necessary_amount)
    else:
        tx_hash = None

    return tx_hash, used_txs


def get_tx_info(tx):
    """ Gets the basic information from a given bitcoin transaction of the testnet.

    :param tx: transaction from where the information is requested.
    :type tx: unicode
    :return: A dictionary containing the input address, the output address, the bitcoin amount transferred in the transaction and the number of confirmations.
    :rtype: dict
    """

    input_addresses = []
    output_addresses = []
    payments = []

    try:
        response = json.loads(make_request('http://tbtc.blockr.io/api/v1/tx/info/' + tx))
    except Exception as e:
        status = json.loads(e.message).get('status')
        if status in ['error', 'fail']:
            return {'from': None, 'to': None, 'amount': None, 'confirmations': 0}

    vins = response.get('data').get('vins')
    vouts = response.get('data').get('vouts')
    confirmations = response.get('data').get('confirmations')

    for i in range(len(vins)):
        if vins[i].get('address') not in input_addresses:
            input_addresses.append(vins[i].get('address'))
    for i in range(len(vouts)):
        output_addresses.append(vouts[i].get('address'))
        payments.append(vouts[i].get('amount'))

    return {'from': input_addresses, 'to': output_addresses, 'amount': payments, 'confirmations': confirmations}


def is_spent(tx_hash, index):
    """
    Checks if a certain output of a transaction is spent.

    :param tx_hash: hash of the transaction to be checked.
    :type tx_hash: str
    :param index: index of the transaction output that will be check.
    :type  index: int
    :return: True if the output is spent, False otherwise.
    :rtype: bool
    """
    try:
        response = make_request('http://tbtc.blockr.io/api/v1/tx/info/' + tx_hash)
        data = json.loads(response)
        result = bool(data['data']['vouts'][index]['is_spent'])
    except Exception as e:
        result = True

    return result


def history_testnet(btc_address):
    """ Gets the history of transaction from a given bitcoin address from the testnet. This function is analogous to the vbuterin's history function from the bitcointools library
    (used all over the code) but using testnet instead of main bitcoin network.

    :param btc_address:  given bitcoin address.
    :type btc_address: str
    :return: The history of transaction from the given address, limited to 200 (from the blockr.io api).
    :rtype: list
    """
    history = []
    response = json.loads(make_request('http://tbtc.blockr.io/api/v1/address/txs/' + btc_address))
    if response.get('status') == 'success':
        data = response.get('data')
        txs = data.get('txs')

        for tx in reversed(txs):
            history.append(get_tx_info(tx.get('tx')))

    return history


def push_tx(tx, network='testnet', fee=False):
    """ Pushes a transaction to the bitcoin network (the testnet by default) with 0 fees.

    :param tx: transaction to be pushed.
    :type tx: unicode
    :param network: network where the transaction will be pushed.
    :type network: str
    :param fee: if set a fee will be applied to the transaction.
    :type fee: bool
    :return: A result consisting on a code (201 if success), a response reason, and the hash of the transaction.
    :rtype: int, str, str
    """

    if network in ['testnet', 'main']:
        if network is 'testnet':
            if fee:
                url = 'http://tbtc.blockr.io/api/v1/tx/push'
            else:
                url = 'https://api.blockcypher.com/v1/btc/test3/txs/push'
        elif network is 'main':
            if fee:
                url = 'http://btc.blockr.io/api/v1/tx/push'
            else:
                url = 'https://api.blockcypher.com/v1/btc/main/txs/push'

        if fee:
            data = {'hex': tx}
        else:
            data = {'tx': tx}

        response = post(url, data=json.dumps(data))
    else:
        response = 'Bad network'

    r_code = response.status_code
    r_reason = response.reason

    if r_code is 200:
        # blockr server
        pushed_tx = json.loads(response.content)
        tx_hash = str(pushed_tx['data'])
    elif r_code is 201:
        # blockcyper server
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
    :param hashcode: indicates which parts of the transaction will be signed. It is set to all by default.

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
        prev_tx_info = get_tx_info(prev_tx_hash)
        if btc_address in prev_tx_info['to']:
            index = prev_tx_info['to'].index(btc_address)

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


def check_txs_source(btc_address, dcs_address, certs_path):
    """ Checks if the sources of the funds of the provided bitcoin address are valid.
        Valid sources are:

        - A previous certified CS (just for the first transaction in the address history).
        - The DCS.

    :param btc_address: bitcoin address that will be checked.
    :type btc_address: str
    :param dcs_address: bitcoin address of the DCS.
    :type dcs_address: str
    :param certs_path: path to the folder in which the certificates are stored.
    :type certs_path: str
    :return: True if the sources are valid. False otherwise.
    :rtype: bool
    """
    txs_history = history_testnet(btc_address)
    response = True

    for i in range(len(txs_history)):
        src = txs_history[i].get("from")
        to = txs_history[i].get("to")
        # If the address that we are checking is the destination of a transaction
        if btc_address in to:
            # If is the first transaction in the address history it could come from previously certified CS or from the DCS
            if i is 0:
                # ToDo: Check "check_certificate" ToDo.
                certified_cs = []
                for address in src:
                    if address != dcs_address:
                        certified_cs.append(check_certificate(address, certs_path))

                if False in certified_cs:
                    response = False
            # If is not the first transaction, it could only come from one source, that must be the DCS or the same CS
            else:
                if len(src) is 1:
                    if src[0] != dcs_address and src[0] != btc_address:
                        response = False
                else:
                    response = False

    return response


def local_push(tx, rpc_user=None, rpc_password=None):
    """ Pushes a bitcoin transaction to the network using a local rpc server.

    :param tx: transaction to be pushed.
    :type tx: hex str
    :param rpc_user: rpc user (could be set in bitcoin.conf).
    :type rpc_user: str
    :param rpc_password: rpc password ((could be set in bitcoin.conf).
    :type rpc_password: str
    :return: The response of the rpc server, corresponding to the transaction id if it has ben correctly pushed
    """
    # Just for testing, having some problems with blockr push_tx
    if rpc_user is None and rpc_password is None:
        rpc_user = "sr_gi"
        rpc_password = "Aqx1xL47eZiKN8v5XjNaJawbmmaMwUKHyTTWEHzrvUbD"

    rpc_connection = AuthServiceProxy("http://"+rpc_user+":"+rpc_password+"@127.0.0.1:18332")

    try:
        response = rpc_connection.sendrawtransaction(tx)
        print "Transaction broadcast " + response
    except JSONRPCException as e:
        print e.message
        response = None

    return response

