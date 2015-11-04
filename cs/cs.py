from ConfigParser import ConfigParser
from urllib2 import urlopen, URLError
from hashlib import sha256
from os import rename
from time import time
from json import dumps
from base64 import b64encode, b64decode
from random import randint, getrandbits
from requests import post
from os import mkdir, path
from shutil import rmtree
from M2Crypto import EC, BIO, EVP, ASN1, RSA, X509
from pyasn1_modules.rfc2459 import Certificate
from pyasn1_modules.rfc2314 import Signature
from pyasn1.codec.der import encoder, decoder
from Crypto.PublicKey import RSA as tbRSA
from Crypto.Util.number import long_to_bytes

from utils.bitcoin.tools import get_pub_key_hex, public_key_to_btc_address, btc_address_from_cert, get_balance, private_key_to_wif, get_priv_key_hex
from utils.bitcoin.transactions import reputation_transfer, blockr_unspent
from utils.certificate.tools import store_certificate

__author__ = 'sdelgado'

############################
#     GLOBAL VARIABLES     #
############################

# Paths to local files
P_KEY = 'paysense_public.key'
S_KEY = 'private/paysense.key'
CERT = 'paysense.crt'
WIF = 'wif_qr.png'
tmp = "_tmp/"

# Configuration file data loading
config = ConfigParser()
config.read("paysense.conf")

DCS = config.get("Servers", "DCS", )
ACA = config.get("Servers", "ACA", )
RAND_SIZE = int(config.get("Misc", "RandomSize"))
CERT_COUNT = int(config.get("Misc", "CertCount"))


class CS(object):
    def __init__(self, data_path):
        self.data_path = data_path
        self.btc_address = []

    # Generates the CS EC keys.
    def generate_keys(self):
        # Generate the elliptic curve and the keys
        ec = EC.gen_params(EC.NID_secp256k1)
        ec.gen_key()

        # Generate a Pkey object to store the EC keys
        mem = BIO.MemoryBuffer()
        ec.save_pub_key_bio(mem)
        ec.save_key_bio(mem, None)
        pk = EVP.load_key_bio(mem)

        # Generate the bitcoin address from the public key
        public_key_hex = get_pub_key_hex(ec.pub())
        bitcoin_address = public_key_to_btc_address(public_key_hex, 'test')
        self.btc_address.append(bitcoin_address)

        # Save both keys
        if not path.exists(tmp):
            mkdir(tmp)
        ec.save_key(tmp + bitcoin_address + '_key.pem', None)
        ec.save_pub_key(tmp + bitcoin_address + '_public_key.pem')

        # Create the WIF file
        wif = private_key_to_wif(get_priv_key_hex(tmp + bitcoin_address + '_key.pem'), 'image', 'test')
        wif.save(tmp + bitcoin_address + "_WIF.png")

        return pk, bitcoin_address

    def generate_certificate(self, aca_cert):

        pkey, btc_address = self.generate_keys()

        issuer = aca_cert.get_issuer()

        # Creating a certificate
        cert = X509.X509()

        # Set issuer
        cert.set_issuer(issuer)

        # Generate CS information
        cert_name = X509.X509_Name()
        cert_name.C = 'CT'
        cert_name.ST = 'Barcelona'
        cert_name.L = 'Bellaterra'
        cert_name.O = 'UAB'
        cert_name.OU = 'DEIC'
        cert_name.CN = btc_address
        cert.set_subject_name(cert_name)

        # Set public_key
        cert.set_pubkey(pkey)

        # Time for certificate to stay valid
        cur_time = ASN1.ASN1_UTCTIME()
        cur_time.set_time(int(time()))
        # Expire certs in 1 year.
        expire_time = ASN1.ASN1_UTCTIME()
        expire_time.set_time(int(time()) + 60 * 60 * 24 * 365)
        # Set the validity
        cert.set_not_before(cur_time)
        cert.set_not_after(expire_time)

        # # Sign the certificate using the same key type the CA is going to use later
        rsa_keys = RSA.gen_key(2046, 65537, callback=lambda x, y, z: None)
        rsa_pkey = EVP.PKey()
        rsa_pkey.assign_rsa(rsa_keys)
        cert.sign(rsa_pkey, md='sha256')

        # Load the Certificate as a ASN.1 object and extract the TBS Certificate (special thanks to Alex <ralienpp@gmail.com>)
        asn1_cert = decoder.decode(cert.as_der(), asn1Spec=Certificate())[0]
        tbs = asn1_cert.getComponentByName("tbsCertificate")

        # Compute the sha256 of the TBS Certificate
        tbs_der = encoder.encode(tbs)
        digest = sha256()
        digest.update(tbs_der)
        cert_hash = digest.digest()

        return asn1_cert, cert_hash

    # CS registration
    def registration(self, filename='paysense'):
        certs, certs_der, cert_hashes, blinded_hashes, rands = [], [], [], [], []

        # Create the directories if they don't exist already
        if not path.exists(self.data_path):
            mkdir(self.data_path)

        if not path.exists(self.data_path + "private"):
            mkdir(self.data_path + "private")

        try:
            # Get ACA information
            aca_cert_text = b64decode(urlopen(ACA + '/get_ca_cert').read())
            aca_cert = X509.load_cert_string(aca_cert_text)
            pk = tbRSA.importKey(aca_cert.get_pubkey().as_der())

            # Generate the basic certificates
            for i in range(CERT_COUNT):
                cert, cert_hash = self.generate_certificate(aca_cert)
                certs.append(cert)
                cert_hashes.append(cert_hash)

                # Blind the cert hash
                rands.append(getrandbits(RAND_SIZE))
                blinded_hashes.append(pk.blind(cert_hashes[i], rands[i]))

            # Contact the ACA and send her the certificate hash to be signed
            headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
            data = {'cert_hashes': b64encode(str(blinded_hashes)), 'step': 1}

            response = post(ACA + "/sign_in", data=dumps(data), headers=headers)

            # If response is OK
            if response.status_code is 200:
                p = int(b64decode(response.content))

                # Prepare the data to be sent to the ACA
                for i in range(len(certs)):
                    if i != p:
                        certs_der.append(encoder.encode(certs[i]))
                    else:
                        # The data in the chosen position is deleted and not sent to the ACA
                        certs_der.append(None)
                        r = rands[i]
                        rands[i] = 0

                # Send the data to the ACA
                data = {'certs': b64encode(str(certs_der)), 'rands': str(rands), 'step': 2}
                response = post(ACA + "/sign_in", data=dumps(data), headers=headers)

                # If response is OK
                if response.status_code is 200:
                    signed_b_hash = b64decode(response.content)
                    signature = pk.unblind(long(signed_b_hash), r)

                    # Check that the signature is valid
                    if pk.verify(cert_hashes[p], [signature, 0]):
                        # Attach the signature to the certificate
                        bin_signature = Signature("'%s'H" % ''.join("%02X" % ord(c) for c in long_to_bytes(signature)))
                        certs[p].setComponentByName("signatureValue", bin_signature)

                        # Set the bitcoin address to the chosen one
                        self.btc_address = self.btc_address[p]

                        # Rename and move the keys associated with the chosen bitcoin address
                        if not path.exists(self.data_path + "/private"):
                            mkdir(self.data_path + "private")
                        rename(tmp + self.btc_address + "_key.pem", self.data_path + "/private/paysense.key")
                        rename(tmp + self.btc_address + "_public_key.pem", self.data_path + "paysense_public.key")
                        rename(tmp + self.btc_address + "_WIF.png", self.data_path + "private/wif_qr.png")

                        # Delete the temp folder and all the other keys
                        rmtree(tmp)

                        # Store the certificate
                        # final_cert = X509.load_cert_der_string(encoder.encode(certs[p]))
                        store_certificate(encoder.encode(certs[p]), self.data_path + filename)

                        # Get the certificate from the just created file with it's new format
                        f = open(self.data_path + filename + '.crt')
                        certificate = f.read()
                        f.close()

                        # Send the final certificate to the ACA
                        data = {'certificate': certificate, 'bitcoin_address': self.btc_address}
                        response = post(ACA + "/store_certificate", data=dumps(data), headers=headers)

                        return response
                    else:
                        return "Invalid certificate signature"
                else:
                    return response
            else:
                return response
        except URLError as e:
            return e

    # Reports the data gathered by the CS
    def report_data(self, message, certificate=False):

        bitcoin_address = btc_address_from_cert(self.data_path + CERT)

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

        r = post(DCS, data=dumps(data), headers=headers)

        return r.status_code, r.reason, r.content

    # This test emulates the CS reputation exchange when he doesn't trust any other CS nor the ACA
    def self_reputation_exchange(self, new_btc_address, outside_btc_address=None):

        bitcoin_address = btc_address_from_cert(self.data_path + CERT)

        address_balance = get_balance(bitcoin_address)

        if outside_btc_address is not None:
            # ToDo: Perform a proper way to withdraw reputation
            reputation_withdraw = (float(randint(2, 5)) / 100) * address_balance
            reputation_transfer(self.data_path + S_KEY, bitcoin_address, new_btc_address, address_balance, outside_btc_address, int(reputation_withdraw))
        else:
            reputation_transfer(self.data_path + S_KEY, bitcoin_address, new_btc_address, address_balance)

        response = urlopen(ACA + '/reputation_exchange?new_btc_address=' + new_btc_address)

        return response

    def coinjoin_reputation_exchange(self, amount, fee=1000):

        # Get the current bitcoin address
        bitcoin_address = btc_address_from_cert(self.data_path + CERT)

        # Get the address current balance
        address_balance = get_balance(bitcoin_address)

        # Get the address utxo set
        utxo_set = blockr_unspent(bitcoin_address, 'testnet')

        if len(utxo_set) is 1 and address_balance == amount + fee:
            # Case 0
            # The address has already only one utxo with the desired value, that one could be used as input for the reputation transfer protocol.
            transaction_hash = utxo_set[0].get("output")

        elif len(utxo_set) > 1:
            # Case 1
            if address_balance is amount + 2 * fee:
                # Perform a transaction to oneself in order to transform all the bitcoin utxo in a single one with the total value.
                # Fees will be payed twice here since two transaction have to be performed
                transaction_hash, used_tx = reputation_transfer(self.data_path + S_KEY, bitcoin_address, bitcoin_address, address_balance)
                # Add the output index. Since the transaction has always only one output, it will be always 0.
                transaction_hash += ":0"
            elif address_balance > amount + 2 * fee:
                # Case 2-3
                # If there's a lot of utxos we should look for one that has the amount we are looking for.
                utxo_n = None
                for utxo in utxo_set:
                    if utxo("value") == amount + fee:
                        utxo_n = utxo
                        break

                # If we find that transaction, it could be used as input of the reputation transfer protocol.
                if utxo_n is not None:
                    # Case 2
                    transaction_hash = utxo_n.get("output")
                # Otherwise, a transaction with the desired amount to oneself should be performed in order to use that output as input of the next transaction.
                # Fees will be payed twice here since two transaction have to be performed.
                else:
                    # Case 3
                    transaction_hash, used_tx = reputation_transfer(self.data_path + S_KEY, bitcoin_address, bitcoin_address, amount + fee)
                    transaction_hash += ":0"
            else:
                transaction_hash = None
        else:
            transaction_hash = None

        if transaction_hash is not None:

            # Create the address that will be used as a new pseudonym
            new_btc_addr_pk, new_btc_addr = self.generate_keys()

            # Build the output of the mixing transaction
            mixing_output = [{'value': amount, 'address': new_btc_addr}]

            # Build the input of the mixing transaction
            mixing_input = [{'output': transaction_hash, 'value': amount + fee}]



        else:
            return "You have not enough reputation to perform a reputation exchange. Minimum amount: " + str(amount) + " + " + str(fee) + " (transaction fee)."
