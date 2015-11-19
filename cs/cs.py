from ConfigParser import ConfigParser
from urllib2 import urlopen, URLError
from hashlib import sha256
from os import rename
from time import time, sleep
from json import dumps, loads
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
from stem.control import Controller

from utils.bitcoin.tools import get_pub_key_hex, public_key_to_btc_address, btc_address_from_cert, get_balance, private_key_to_wif, get_priv_key_hex
from utils.bitcoin.transactions import reputation_transfer, blockr_unspent, get_tx_signature
from utils.certificate.tools import store_certificate
from utils.tor.tools import tor_query, init_tor

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
    def __init__(self, data_path, new=False):
        self.data_path = data_path
        if new:
            self.btc_address = None
        else:
            self.btc_address = btc_address_from_cert(self.data_path + CERT)

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

        # Save both keys
        if not path.exists(self.data_path + tmp):
            mkdir(self.data_path + tmp)
        ec.save_key(self.data_path + tmp + bitcoin_address + '_key.pem', None)
        ec.save_pub_key(self.data_path + tmp + bitcoin_address + '_public_key.pem')

        # Create the WIF file
        wif = private_key_to_wif(get_priv_key_hex(self.data_path + tmp + bitcoin_address + '_key.pem'), 'image', 'test')
        wif.save(self.data_path + tmp + bitcoin_address + "_WIF.png")

        return pk, bitcoin_address

    def generate_certificate(self, aca_cert, btc_address=None, pkey=None,):

        if pkey is None and btc_address is None:
            pkey, btc_address = self.generate_keys()
            self.btc_address = btc_address

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

        # Sign the certificate using the same key type the CA is going to use later
        # The resulting signature will not be used, it is only for setting the corresponding field into the certificate
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

    def generate_new_identity(self, new_btc_addr, new_pk, filename='paysense'):

        new_dir = "old/" + self.btc_address + "/"

        # Create an 'old' directory if it doesn't exist
        if not path.exists(self.data_path + 'old'):
            mkdir(self.data_path + 'old')

        # Create a directory named by the bitcoin address inside the 'old' directory
        if not path.exists(self.data_path + new_dir):
            mkdir(self.data_path + new_dir)

        # Move all the old data to its new directory
        rename(self.data_path + "private", self.data_path + new_dir + "private")
        rename(self.data_path + filename + ".crt", self.data_path + new_dir + filename + ".crt")
        rename(self.data_path + filename + "_public.key", self.data_path + new_dir + filename + "_public.key")
        if path.exists(self.data_path + self.btc_address):
            rename(self.data_path + self.btc_address, self.data_path + new_dir + self.btc_address)

        aca_cert_text = b64decode(urlopen(ACA + '/get_ca_cert').read())
        aca_cert = X509.load_cert_string(aca_cert_text)

        asn1_cert, cert_hash = self.generate_certificate(aca_cert, new_btc_addr, new_pk)

        # Create a 'private' directory
        if not path.exists(self.data_path + 'private'):
            mkdir(self.data_path + 'private')

        # Create the new identity files
        rename(self.data_path + tmp + new_btc_addr + "_key.pem", self.data_path + "private/" + filename + ".key")
        rename(self.data_path + tmp + new_btc_addr + "_public_key.pem", self.data_path + filename + "_public.key")
        rename(self.data_path + tmp + new_btc_addr + "_WIF.png", self.data_path + "private/wif_qr.png")
        f = open(self.data_path + new_btc_addr, 'w')
        f.close()
        rmtree(self.data_path + tmp)

        certificate = b64encode(encoder.encode(asn1_cert))
        # Send the final certificate to the ACA
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        data = {'certificate': certificate, 'bitcoin_address': new_btc_addr}
        response = post(ACA + "/sign_certificate", data=dumps(data), headers=headers)

        # Store the certificate
        cert_der = b64decode(response.content)
        store_certificate(cert_der, self.data_path + filename)

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
                        rename(self.data_path + tmp + self.btc_address + "_key.pem", self.data_path + "/private/paysense.key")
                        rename(self.data_path + tmp + self.btc_address + "_public_key.pem", self.data_path + "paysense_public.key")
                        rename(self.data_path + tmp + self.btc_address + "_WIF.png", self.data_path + "private/wif_qr.png")

                        # Delete the temp folder and all the other keys
                        rmtree(self.data_path + tmp)

                        # Store the certificate
                        der_cert = encoder.encode(certs[p])
                        store_certificate(der_cert, self.data_path + filename)

                        # Send the final certificate to the ACA
                        data = {'certificate': b64encode(der_cert), 'bitcoin_address': self.btc_address}
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

        # Load CS private key
        ec = EC.load_key(self.data_path + S_KEY)

        signature = ec.sign_dsa_asn1(message)
        signature = b64encode(signature)

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        data = {'message': message, 'signature': signature, 'bitcoin_address': self.btc_address}

        if certificate is True:
            f = open(self.data_path + CERT, 'r')
            cs_pem_data = b64encode(f.read())
            f.close()
            data['cs_pem_data'] = cs_pem_data

        r = post(DCS, data=dumps(data), headers=headers)

        return r.status_code, r.reason, r.content

    # This test emulates the CS reputation exchange when he doesn't trust any other CS nor the ACA
    def self_reputation_exchange(self, new_btc_address, outside_btc_address=None, fee=1000):

        address_balance = get_balance(self.btc_address)

        if outside_btc_address is not None:
            # ToDo: Perform a proper way to withdraw reputation
            reputation_withdraw = (float(randint(2, 5)) / 100) * address_balance
            tx_hash, _ = reputation_transfer(self.data_path + S_KEY, self.btc_address, new_btc_address, address_balance, outside_btc_address, int(reputation_withdraw) - fee, fee)
        else:
            tx_hash, _ = reputation_transfer(self.data_path + S_KEY, self.btc_address, new_btc_address, address_balance - fee, fee=fee)

        response = urlopen(ACA + '/reputation_exchange?new_btc_address=' + new_btc_address)

        return response

    def coinjoin_reputation_exchange(self, amount, fee=1000):

        # Get onion server address and the mixing amount from the ACA
        data = loads(urlopen(ACA + '/get_tor_address').read())
        tor_server = data.get("address")
        mixing_amount = data.get("amount")

        if mixing_amount == amount:

            utxo = self.get_mixing_utxo(amount, fee)

            if utxo is not None:

                # Create the address that will be used as a new pseudonym
                new_btc_addr_pk, new_btc_addr = self.generate_keys()

                # Build the output of the mixing transaction
                mixing_output = [{'value': amount, 'address': new_btc_addr}]

                # Build the input of the mixing transaction
                mixing_input = [{'output': utxo, 'value': amount + fee}]

                print "Connecting to " + tor_server
                # ToDo: Uncomment, actually running tor from terminal since testing server and client from the same machine
                # print(term.format("Starting Tor:\n", term.Attr.BOLD))
                # tor_process, controller = init_tor()

                # ToDo: Delete the following two lines when the above one is uncommented
                controller = Controller.from_port()
                controller.authenticate()

                headers = ['Content-type: application/json', 'Accept: text/plain']
                # Send reputation exchange output
                data = dumps({'outputs': mixing_output})
                code, response = tor_query(tor_server + "/outputs", 'POST', data, headers)

                if code is 200:
                    print "Output correctly sent. Resetting tor connection"
                    controller.new_circuit()

                    timer = float(loads(response).get("data"))
                    print "Waiting " + str(timer) + " for sending the input"
                    sleep(timer)

                    # Send reputation exchange input
                    data = dumps({'inputs': mixing_input})
                    code, response = tor_query(tor_server + "/inputs", 'POST', data, headers)

                    if code is 200:
                        print "Input correctly sent. Resetting tor connection"
                        controller.new_circuit()

                        timer = float(loads(response).get("data"))
                        print "Waiting " + str(timer) + " for getting the tx to be signed"
                        sleep(timer)

                        # Get tx hash to sign it
                        code, response = tor_query(tor_server + '/signatures')

                        if code is 200:
                            private_key_hex = get_priv_key_hex(self.data_path + S_KEY)
                            public_key = EC.load_pub_key(self.data_path + P_KEY)
                            public_key_hex = get_pub_key_hex(public_key.pub())

                            signature, index = get_tx_signature(response, private_key_hex, self.btc_address)

                            data = {'signature': signature, 'index': index, 'public_key': public_key_hex}
                            data = dumps({'data': data})

                            code, response = tor_query(tor_server + "/signatures", 'POST', data, headers)

                            if code is 200:
                                timer = float(loads(response).get("data"))
                                print "Waiting " + str(timer) + " for the transaction to be completed"
                                sleep(timer)
                                confirmed = False

                                while not confirmed:
                                    code, response = tor_query(tor_server + '/confirmation')
                                    data = loads(response)
                                    confirmed = bool(data.get("confirmation"))
                                    timer = float(data.get("time"))
                                    print "Waiting " + str(timer) + " for the transaction correctness confirmation"
                                    sleep(timer)

                                print "Transaction confirmed"
                                self.generate_new_identity(new_btc_addr, new_btc_addr_pk)
                                data = loads(response).get("data")
                                result = data
                            else:
                                try:
                                    data = loads(response).get("data")
                                    result = data
                                except ValueError:
                                    result = "Error sending signatures. " + str(response)
                        else:
                            try:
                                data = loads(response).get("data")
                                result = data
                            except ValueError:
                                result = "Error getting signatures. " + str(response)
                    else:
                        try:
                            data = loads(response).get("data")
                            result = data
                        except ValueError:
                            result = "Error sending inputs. " + str(response)
                else:
                    try:
                        data = loads(response).get("data")
                        result = data
                    except ValueError:
                        result = "Error sending outputs. " + str(response)

            else:
                result = "You have not enough reputation to perform a reputation exchange. Minimum amount: " + str(amount) + " + " + str(fee) + " (transaction fee)."
        else:
            result = "The mixing server does not provide a mixing process for the chosen reputation amount"

        return result

    def get_mixing_utxo(self, amount, fee):

        # Get the address current balance
        address_balance = get_balance(self.btc_address)

        # Get the address utxo set
        utxo_set = blockr_unspent(self.btc_address, 'testnet')

        transaction_hash = None

        if address_balance == amount + fee and len(utxo_set) is 1:
            # Case 0. If the address balance is exactly amount + fee the only way to perform the transaction is if there is only one utxo. Otherwise, some balance would be expended to
            # create a utxo with amount + fee and the total balance will be reduced, concluding in a balance < amount + fee.
            transaction_hash = utxo_set[0].get("output")
        elif address_balance > amount + fee:
            # If the balance is greater that amount + fee, a utxo with the exact amount ( amount + fee) will be looked for in the utxo pool.
            utxo_n = None
            for utxo in utxo_set:
                if utxo.get("value") == amount + fee:
                    utxo_n = utxo
                    break
            # Case 2. If it could be found, that will be the utxo to be used.
            if utxo_n is not None:
                transaction_hash = utxo_n.get("output")

            # Case 1 and 3. Otherwise, a transaction to create a utxo of amount + fee should be performed, only if the balance is greater that amount + 2 fee.
            elif address_balance >= amount + 2 * fee:
                transaction_hash, used_tx = reputation_transfer(self.data_path + S_KEY, self.btc_address, self.btc_address, amount + fee, fee=fee)
                if transaction_hash is not None:
                    transaction_hash += ":0"

        return transaction_hash
