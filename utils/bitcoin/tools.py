import requests
import qrcode
from base58 import b58encode
from binascii import a2b_hex, b2a_hex
from asn1tinydecoder import *
from subprocess import check_output, STDOUT
from bitcoin import *
from flask import json
from M2Crypto import X509

PUBKEY_HASH = 0
TESTNET_PUBKEY_HASH = 111
WIF = 128
TESTNET_WIF = 239


def hash_160(public_key):
    """ Calculates the RIPEMD-160 hash of a given elliptic curve key.
    :param public_key: is an elliptic public key (in hexadecimal format).
    :return: the RIPEMD-160 hash as a byte array.
    """
    md = hashlib.new('ripemd160')
    sha256 = hashlib.sha256(a2b_hex(public_key)).digest()
    md.update(sha256)
    return md.digest()


def hash_160_to_btc_address(h160, v):
    """ Calculates the bitcoin address of a given RIPEMD-160 hash from a elliptic curve public key.
    :param h160: is the RIPEMD-160 hash.
    :param v: is the version (prefix) used to calculate the bitcoin address. The possible values are 0 (for main network) and 111 (for testnet)
    :return: the corresponding bitcoin address as a hexadecimal string.
    """
    vh160 = chr(v) + h160
    h = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()
    addr = vh160 + h[0:4]
    return b58encode(addr)


def public_key_to_btc_address(public_key, v='main'):
    """ Calculates the bitcoin address of a given elliptic curve public key
    :param public_key: is a elliptic curve public key (in hexadecimal format).
    :param v: is the version used to calculate the bitcoin address. If v is 'test' a testnet bitcoin address will be calculated. Otherwise, it will be a main network one.
    :return: the corresponding bitcoin address as a hexadecimal string.
    """
    if v is 'test':
        v = TESTNET_PUBKEY_HASH
    else:
        v = PUBKEY_HASH
    h160 = hash_160(public_key)
    return hash_160_to_btc_address(h160, v)


# ToDO: Change the function to use pyasn1 instead of asn1tinydecoder
def get_pub_key_hex(public_key):
    """ Gets a public key in hexadecimal format from a OpenSSL public key object.
    :param public_key: is an OpenSSL public key object.
    :return: the hexadecimal representation of the public key.
    """
    der = public_key.get_der()
    root = asn1_node_root(der)
    key = b2a_hex(asn1_get_value(der, asn1_node_next(der, asn1_node_first_child(der, root))))
    return key[2:]


# ToDO: Find a way to get the SK without a system call
def get_priv_key_hex(pk_file_path):
    """ Gets the private key in hexadecimal format from a key file
    :param pk_file_path: is the system path where the private key is found.
    :return: the hexadecimal representation of the private key.
    """
    cmd = ['openssl', 'ec', '-in', pk_file_path, '-text', '-noout']
    response = check_output(cmd, stderr=STDOUT)

    raw_key = response[response.find('priv:') + 8: response.find('pub:')]
    raw_key = raw_key.replace(":", "")
    raw_key = raw_key.replace(" ", "")
    raw_key = raw_key.replace("\n", "")

    # If the key starts with 00, the two first characters are removed
    if raw_key[:2] == '00':
        private_key_hex = raw_key[2:]
    else:
        private_key_hex = raw_key

    return private_key_hex


def private_key_to_wif(private_key, mode='text', v='main'):
    """ Generates a WIF representation of a provided private key.
    :param private_key: is an elliptic curve key (in hex format).
    :param mode: defines the typer of return. If mode is 'text' a String will be returned. Otherwise, it will return a qrcode object.
    :param v: is the version (prefix) used to calculate the WIF, it depends on the type of network. If v is 'test' it will generate a testnet WIF, otherwise it will return a main network one.
    :return: the WIF representation of the private key.
    """
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

    if mode is 'text':
        response = wif
    else:
        response = qrcode.make(wif)

    return response


def btc_address_from_cert(certificate):
    """ Gets a bitcoin address from a PaySense x.509 certificate (stored in the CN field of it).
    :param certificate: is the path of a file containing a X.509 certificate.
    :return: the corresponding bitcoin address.
    """
    certificate = X509.load_cert(certificate)
    details = certificate.get_subject().as_text()
    btc_address = details[details.find('CN') + 3:]

    return btc_address


def tx_info(tx):
    """ Gets the basic information from a given bitcoin transaction of the testnet.
    :param tx: is the transaction.
    :return: a JSon object containing the input address, the output address, the bitcoin amount transferred in the transaction and the number of confirmations.
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


def history_testnet(bitcoin_address):
    """ Gets the history of transaction from a given bitcoin address from the testnet. This function is analogous to the vbuterin's history function from the bitcointools library
    (used all over the code) but using testnet instead of main bitcoin network
    :param bitcoin_address:  is the given bitcoin address
    :return: the history of transaction from the given address, limited to 200 (from the blockr.io api)
    """
    history = []
    response = json.loads(make_request('http://tbtc.blockr.io/api/v1/address/txs/' + bitcoin_address))
    if response.get('status') == 'success':
        data = response.get('data')
        txs = data.get('txs')

        for i in range(len(txs)):
            history.append(tx_info(txs[i].get('tx')))

    return history


def push_tx(tx, network='testnet'):
    """ Pushes a tx to the bitcoin network (the testnet by default) with 0 fees.
    :param tx: is the transaction to be pushed.
    :param network: is the network where the transaction will be pushed.
    :return: a result consisting on a code (201 if success), a response reason, and the hash of the transaction.
    """
    if network in ['testnet', 'main']:
        if network is 'testnet':
            url = 'https://api.blockcypher.com/v1/btc/test3/txs/push'
        elif network is 'main':
            url = 'https://api.blockcypher.com/v1/btc/main/txs/push'

        data = {'tx': tx}
        response = requests.post(url, data=json.dumps(data))
    else:
        response = 'Bad network'

    r_code = response.status_code
    r_reason = response.reason
    pushed_tx = json.loads(response.content)
    tx_hash = str(pushed_tx['tx']['hash'])

    return r_code, r_reason, tx_hash


def get_balance(bitcoin_address, network='testnet'):
    """ Gets the balance of a given bitcoin address from a given network.
    :param bitcoin_address: is the bitcoin address from which the balance will be calculated.
    :param network: is the bitcoin network where the address comes from (testnet by default).
    :return: the bitcoin address balance (in Satoshi).
    """
    if network in ['testnet', 'main']:
        if network is 'testnet':
            url = 'http://tbtc.blockr.io/api/v1/address/balance/'
        elif network is 'main':
            url = 'http://btc.blockr.io/api/v1/address/balance/'

    response = json.loads(make_request(url + bitcoin_address))

    return int(100000000 * response['data']['balance'])


def get_necessary_amount(unspent_transactions, amount, size='small'):
    """ Calculates the minimum necessary amount needed to pay the required bitcoins of a transaction.
    :param unspent_transactions: is a list of the unspent transactions from a bitcoin address
    :param amount: is the desired amount to be paid.
    :param size: if size is 'big' the unspent bitcoins will be spent from the bigger groups to the smaller. Otherwise, it will be used in the opposite way.
    :return: a list with the unspent bitcoins to be used, and the total amount of them (that will be at least equal to :param amount)
    """
    if len(unspent_transactions) is 0 or unspent_transactions is None:
        necessary_amount = []
        total_amount = 0
    else:
        if size == 'small':
            unspent_bitcoins = sorted(unspent_transactions, key=lambda item: item['value'])
        else:
            # Sort the transactions from less to more amount
            unspent_bitcoins = sorted(unspent_transactions, key=lambda item: item['value'], reverse=True)

        # Get all the values from the unspent transactions
        values = []
        for transaction in unspent_bitcoins:
            values.append(transaction.get("value"))

        necessary_amount = []

        # Get the minimum amount necessary to perform the tx.

        # First of all, it is looked if there's any previous transaction with the same amount that we want to spent.
        # If so, that transaction will be the chosen one.
        if amount in values:
            necessary_amount.append(unspent_bitcoins[values.index(amount)])
            total_amount = values[values.index(amount)]

        # Otherwise, the transactions with the lesser amount will be added until the necessary requested amount is reached.
        else:
            total_amount = 0
            i = 0
            while total_amount < amount and i < len(unspent_bitcoins):
                necessary_amount.append(unspent_bitcoins[i])
                total_amount += values[i]
                i += 1

            # If we doesn't reach an enough total amount, no transaction could be performed
            if total_amount < amount:
                total_amount = 0
                necessary_amount = []

            # Finally, if the amount of the last added transaction is greater than the amount we were looking for,
            # that last transaction could be used alone.
            elif values[len(necessary_amount) - 1] > amount:
                total_amount = values[len(necessary_amount) - 1]
                necessary_amount = [unspent_bitcoins[len(necessary_amount) - 1]]

    return necessary_amount, total_amount


def get_tx_signature(tx, private_key, btc_address, hashcode=SIGHASH_ALL):
    """  Computes the signature from a given transaction.
    :param tx: is the input transaction.
    :param private_key: is the elliptic curve private key (in hex format) used to sign.
    :param btc_address: is the bitcoin address used as "from" in the transaction (Where the funds came from).
    :param hashcode: indicates which parts of the transaction will be signed. It is set to all by default
    :return: the signature of the transaction, or an error if there's no transaction to sign.
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
    :param tx: is the input transaction.
    :param index: is the input index of the transaction in which the signature must be placed.
    :param signature: is the signature to be inserted.
    :param public_key: is the elliptic curve public key (in hex format) used to insert the signature in the corresponding input.
    :return:
    """
    tx_obj = deserialize(tx)
    tx_obj["ins"][index]["script"] = serialize_script([signature, public_key])

    return serialize(tx_obj)


def split_btc(btc_address, private_key, amount, parts, size='small', fee=False):
    """ Split a large amount of bitcoins in smaller parts.
    :param btc_address: is the bitcoin address used as a source and destination of the transaction.
    :param private_key: is the private key (in hex format) used to sign the transaction.
    :param amount: is the amount of each one of the parts.
    :param parts: is the number of parts of :param amount generated
    :param size: is the size of the unspent bitcoins that will be split. If size is 'small' the smaller unspent bitcoins will be split. Otherwise, the bigger ones will be split.
    :param fee: defines if the transaction will pay fees or not. If fee is 'True' a fee of :param amount will be payed.
    :return: The response of the bitcoin network to the bitcoin split transaction.
    """
    unspent_transactions = blockr_unspent(btc_address, 'testnet')

    if fee:
        necessary_amount, total_amount = get_necessary_amount(unspent_transactions, amount * (parts + 1), size)
    else:
        necessary_amount, total_amount = get_necessary_amount(unspent_transactions, amount * parts, size)

    outs = []

    for i in range(parts - 1):
        outs.append({'value': amount, 'address': btc_address})
        total_amount -= amount

    if fee:
        outs.append({'value': total_amount - amount, 'address': btc_address})
    else:
        outs.append({'value': total_amount, 'address': btc_address})

    tx = mktx(necessary_amount, outs)

    for i in range(len(necessary_amount)):
        tx = sign(tx, i, private_key)

    print tx

    if fee:
        response = blockr_pushtx(tx, "testnet")
    else:
        response = push_tx(tx)

    return response
