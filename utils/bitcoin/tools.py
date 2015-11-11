import qrcode
import transactions
from bitcoin import *
from asn1tinydecoder import *
from base58 import b58encode
from binascii import a2b_hex, b2a_hex
from subprocess import check_output, STDOUT
from flask import json
from M2Crypto import X509

PUBKEY_HASH = 0
TESTNET_PUBKEY_HASH = 111
WIF = 128
TESTNET_WIF = 239


def hash_160(public_key):
    """ Calculates the RIPEMD-160 hash of a given elliptic curve key.

    :param public_key: elliptic public key (in hexadecimal format).
    :type public_key: hex str
    :return: The RIPEMD-160 hash.
    :rtype: bytes
    """
    md = hashlib.new('ripemd160')
    sha256 = hashlib.sha256(a2b_hex(public_key)).digest()
    md.update(sha256)
    return md.digest()


def hash_160_to_btc_address(h160, v):
    """ Calculates the bitcoin address of a given RIPEMD-160 hash from a elliptic curve public key.

    :param h160: RIPEMD-160 hash.
    :type h160: bytes
    :param v: version (prefix) used to calculate the bitcoin address.

     Possible values:

        - 0 for main network (PUBKEY_HASH)
        - 111 For testnet (TESTNET_PUBKEY_HASH)
    :type v: int
    :return: The corresponding bitcoin address.
    :rtype: hex str
    """
    vh160 = chr(v) + h160
    h = hashlib.sha256(hashlib.sha256(vh160).digest()).digest()
    addr = vh160 + h[0:4]
    return b58encode(addr)


def public_key_to_btc_address(public_key, v='main'):
    """ Calculates the bitcoin address of a given elliptic curve public key

    :param public_key: elliptic curve public key.
    :type public_key: hex str
    :param v: version used to calculate the bitcoin address.
    :type v: str
    :return: The corresponding bitcoin address.

        - testnet bitcoin address if v is 'test'.
        - main network address otherwise.
    :rtype: hex str
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

    :param public_key: public key
    :type public_key: OpenSSL.PublicKey
    :return: public key
    :rtype: hex str
    """
    der = public_key.get_der()
    root = asn1_node_root(der)
    key = b2a_hex(asn1_get_value(der, asn1_node_next(der, asn1_node_first_child(der, root))))
    return key[2:]


# ToDO: Find a way to get the SK without a system call
def get_priv_key_hex(pk_file_path):
    """ Gets the EC private key in hexadecimal format from a key file

    :param pk_file_path: system path where the EC private key is found.
    :type pk_file_path: str
    :return: private key.
    :rtype: hex str
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

    :param private_key: elliptic curve key.
    :type private_key: hex str
    :param mode: defines the type of return.
    :type mode: str
    :param v: version (prefix) used to calculate the WIF, it depends on the type of network.
    :type v: str
    :return: The WIF representation of the private key.

        - testnet WIF is v is 'test'.
        - main network WIF otherwise.
    :rtype:

        - str if mode is 'text'
        - qrcode otherwise
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

    :param certificate: path of a file containing a X.509 certificate.
    :type certificate: str
    :return: The corresponding bitcoin address.
    :rtype: str
    """
    certificate = X509.load_cert(certificate)
    details = certificate.get_subject().as_text()
    btc_address = details[details.find('CN') + 3:]

    return btc_address


# ToDo: Raise exception when network not in ['testnet', 'main']
def get_balance(bitcoin_address, network='testnet'):
    """ Gets the balance of a given bitcoin address from a given network.

    :param bitcoin_address: bitcoin address from which the balance will be calculated.
    :type: str
    :param network: bitcoin network where the address comes from (testnet by default).
    :type network: str
    :return: The bitcoin address balance (in Satoshi).
    :rtype: int
    """
    if network in ['testnet', 'main']:
        if network is 'testnet':
            url = 'http://tbtc.blockr.io/api/v1/address/balance/'
        else:
            url = 'http://btc.blockr.io/api/v1/address/balance/'

        r = json.loads(make_request(url + bitcoin_address))
        response = int(round(100000000 * r['data']['balance']))
    else:
        response = "Wrong network\n"
    return response


def get_necessary_amount(unspent_transactions, amount, size='small'):
    """ Calculates the minimum necessary amount needed to pay the required bitcoins of a transaction.

    :param unspent_transactions: list of the unspent transactions from a bitcoin address
    :type unspent_transactions: list
    :param amount: desired amount to be paid.
    :type amount: int
    :param size: represent the size of the bitcoin groups that will be chosen to pay the transaction.

        - the unspent bitcoins will be chosen from the bigger groups to the smaller ones if size is 'big'
        - them will be chosen in the opposite way otherwise.
    :type size: str
    :return: A list with the unspent bitcoins to be used, and the total amount of them (that will be at least equal to **amount**)
    :rtype: list, int
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


def split_btc(btc_address, private_key, amount, parts, size='small', fee=False):
    """ Split a large amount of bitcoins in smaller parts.

    :param btc_address: bitcoin address used as a source and destination of the transaction.
    :type btc_address: str
    :param private_key: private key used to sign the transaction.
    :type private_key: hex str
    :param amount: amount of each one of the parts.
    :type amount: int
    :param parts: number of parts of :param amount generated
    :type parts: int
    :param size: size of the unspent bitcoins that will be split.
    :type size: str

    - the smaller unspent bitcoins will be split is size is 'small'
    - the bigger ones will be split otherwise.

    :param fee: defines if the transaction will pay fees or not. If fee is 'True' a fee of :param amount will be payed.
    :type fee: bool

        - if True, a fee of **amount** will be payed.
        - Otherwise, no fee will be payed.

    :return: The response of the bitcoin network to the bitcoin split transaction.
    :rtype: str
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

    response = transactions.push_tx(tx, fee=fee)

    return response

