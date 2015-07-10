__author__ = 'sdelgado'

from base64 import b64encode
import urllib2

from bitcointools import *
from bitcointransactions import single_payment
from flask import json
from M2Crypto import EC
from random import randint

P_KEY = 'paysense_public.key'
S_KEY = 'private/paysense.key'
CERT = 'paysense.crt'
WIF = 'wif_qr.png'

class CS(object):

    def __init__(self, data_path):
        self.data_path = data_path

    # CS registration
    # ToDo: Change this function to use blind signatures
    def registration(self):
        response = urllib2.urlopen('http://127.0.0.1:5001/sign_in?bitcoin_address=')
        data = json.load(response)
        public_key = data["public_key"]
        private_key = data["private_key"]
        certificate = data["certificate"]

        f = open(self.data_path + P_KEY, 'w')
        f.write(public_key)
        f.close()
        f = open(self.data_path + S_KEY, 'w')
        f.write(private_key)
        f.close()
        f = open(self.data_path + CERT, 'w')
        f.write(certificate)
        f.close()

        s_key = get_priv_key_hex(S_KEY)
        wif_qr = private_key_to_wif(s_key, 'test', 'image')

        wif_qr.save(self.data_path + WIF, "PNG")

    def report_data(self, message, certificate=False):

        bitcoin_address = bc_address_from_cert(self.data_path + CERT)

        # Load CS private key
        ec = EC.load_key(self.data_path + S_KEY)

        signature = ec.sign_dsa_asn1(message)
        signature = b64encode(signature)

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        data = {'message': message, 'signature': signature, 'bitcoin_address': bitcoin_address}

        if certificate is True:
            f = open(self.data_path + CERT, 'r')
            cs_pem_data = b64encode(f.read())
            f.close()
            data['cs_pem_data'] = cs_pem_data

        r = requests.post('http://127.0.0.1:5000', data=json.dumps(data), headers=headers)

        return r.status_code, r.reason, r.content

    # This test emulates the CS reputation exchange when he doesn't trust any other CS nor the ACA
    def self_reputation_exchange(self, new_bc_address, outside_bc_address=None):

        bitcoin_address = bc_address_from_cert(self.data_path + CERT)

        address_balance = get_balance(bitcoin_address)

        if outside_bc_address is not None:
            # ToDo: Perform a proper way to withdraw reputation
            reputation_withdraw = (float(randint(2, 5)) / 100) * address_balance
            single_payment(self.data_path + S_KEY, bitcoin_address, new_bc_address, address_balance, outside_bc_address, int(reputation_withdraw))
        else:
            single_payment(self.data_path + S_KEY, bitcoin_address, new_bc_address, address_balance)


        response = urllib2.urlopen('http://127.0.0.1:5001/reputation_exchange?new_bc_address=' + new_bc_address)

        return response

    def test(self):
        bitcoin_address = bc_address_from_cert(self.data_path + CERT)
        print bitcoin_address

