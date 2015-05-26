__author__ = 'sdelgado'

from base64 import b64encode
from os import path
from os import remove
import time

from flask import Flask, request, jsonify
from M2Crypto import X509, EC, EVP, BIO, ASN1

from bitcointools import public_key_to_bc_address, get_pub_key_hex, history_testnet

app = Flask(__name__)

ACA_CERT = 'ACA/cacert.pem'
ACA_KEY = 'ACA/private/cakey.pem'
CS_CERTS_PATH = 'ACA/newcerts/'

DCS_BC_ADDRESS = 'mqcKJjxaaUcG37MFA3jvyDkaznWs4kyLyg'

def check_certificate(bitcoin_address):
    return path.exists(CS_CERTS_PATH + bitcoin_address + '.pem')

def check_payers(history, expected_payer=None):
    validation = True
    if expected_payer is None:
        expected_payer = DCS_BC_ADDRESS
    if len(history) == 0:
        validation= False
    for i in range(len(history)):
        payer = history[i].get('from')
        if payer is not expected_payer:
            validation = False

    return validation


def generate_response(bitcoin_address):
    # Get data from the pem file, and generate a response
    f = open(bitcoin_address + '_key.pem')
    private_key = f.read()
    f.close()
    f = open(bitcoin_address + '_public_key.pem')
    public_key = f.read()
    f.close()
    f = open(CS_CERTS_PATH + bitcoin_address + '.pem')
    certificate = f.read()
    f.close()
    data = {'public_key': public_key, 'private_key': private_key, 'certificate': certificate}

    # Delete the CS keys
    remove(bitcoin_address + '_public_key.pem')
    remove(bitcoin_address + '_key.pem')

    return data


def store_certificate(certificate, bitcoin_address):
    # Save the pem data into the pem file
    certificate.save_pem(CS_CERTS_PATH + bitcoin_address + '.pem')

    # In order to write the human readable certificate before the encoded data we should load the data just stored
    # and append at the end of the file.
    f = open(CS_CERTS_PATH + bitcoin_address + '.pem', 'r')
    data = f.read()
    f.close()
    f = open(CS_CERTS_PATH + bitcoin_address + '.pem', 'w')
    f.write(certificate.as_text())
    f.write(data)
    f.close()


def generate_certificate(pkey, bitcoin_address):

    # Load ACA certificate
    ca_cert = X509.load_cert(ACA_CERT)
    # Load ACA private key
    ca_pkey = EVP.load_key(ACA_KEY)

    ca_cert.get_issuer()

    # Creating a certificate
    cert = X509.X509()

    # Set CA data
    cert.set_issuer_name(ca_cert.get_subject())

    # Set CS data
    cert_name = X509.X509_Name()
    cert_name.C = 'CA'
    cert_name.ST = 'Barcelona'
    cert_name.L = 'Bellaterra'
    cert_name.O = 'UAB'
    cert_name.OU = 'DEIC'
    cert_name.CN = bitcoin_address
    cert.set_subject_name(cert_name)

    # Set public_key
    cert.set_pubkey(pkey)

    # Time for certificate to stay valid
    cur_time = ASN1.ASN1_UTCTIME()
    cur_time.set_time(int(time.time()))
    # Expire certs in 1 year.
    expire_time = ASN1.ASN1_UTCTIME()
    expire_time.set_time(int(time.time()) + 60 * 60 * 24 * 365)
    # Set the validity
    cert.set_not_before(cur_time)
    cert.set_not_after(expire_time)

    # Sign the certificate using the CA Private Key
    cert.sign(ca_pkey, md='sha256')

    # Store certificate
    store_certificate(cert, bitcoin_address)


#def generate_keys(bitcoin_address):
def generate_keys():

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
    bitcoin_address = public_key_to_bc_address(public_key_hex, 'test')

    # Save both keys
    ec.save_key(bitcoin_address + '_key.pem', None)
    ec.save_pub_key(bitcoin_address + '_public_key.pem')

    #return pk
    return pk, bitcoin_address


def get_cs_certificate(bitcoin_address):
    if check_certificate(bitcoin_address):
        f = open(CS_CERTS_PATH + bitcoin_address + '.pem')
        certificate = f.read()
        f.close()
    else:
        certificate = None

    return certificate


def get_ca_certificate():
    f = open(ACA_CERT)
    certificate = f.read()
    f.close()

    return certificate


@app.route('/get_cs_cert', methods=['GET'])
def api_get_cs_pem():
    # Get the bitcoin_address from the url
    bitcoin_address = request.args.get('bitcoin_address')
    if bitcoin_address is None:
        response = "Invalid parameter.\n"
    else:
        # Look for the digital certificate in the existing ones
        certificate = get_cs_certificate(bitcoin_address)
        if certificate is not None:
            response = b64encode(certificate)
        else:
            response = "There's no digital certificate for the given bc address"

    return response

@app.route('/get_ca_cert', methods=['GET'])
def api_get_ca_pem():
    certificate = get_ca_certificate()
    return b64encode(certificate)


@app.route('/sign_in', methods=['GET'])
def api_sign_in():
    # Get the bitcoin_address from the url
    # Todo: This is a workaround, in this first version the ACA generates either the keys and the certificate
    #bitcoin_address = request.args.get('bitcoin_address')
    #pk = generate_keys(bitcoin_address)
    pk, bitcoin_address = generate_keys()

    # Generate the digital certificate
    generate_certificate(pk, bitcoin_address)

    # Send response to the CS
    response = generate_response(bitcoin_address)

    return jsonify(response)

@app.route('/reputation_exchange', methods=['GET'])
def api_verify_reputation_exchange():
    # Verifies the reputation exchange between a certified bitcoin address, and a new one.
    # Because of in the first version of the PaySense the ACA generate the keys and the certificates, the verification
    # can't be done exactly how it's supposed to be. According to the paper, the requester CS should perform a reputation
    # transaction to a new bitcoin address and send that address to the ACA to be verified and certified. In this version
    # both addresses are already certified, but the ACA checks that the reputation of the new address comes only from the
    # first one, and also that the reputation of the previous address is also correct.

    verified = True

    new_bc_addr = request.args.get('new_bc_address')
    history = history_testnet(new_bc_addr)

    # The new address can only have a single transaction, corresponding to the reputation transaction from the old address
    if len(history) != 1:
        verified = False
    else:
        # If there's only one transaction, the list of from addresses is extracted from the history and it's verified that
        # all the addresses in the list are the same one, that will match with the old_bc_address
        from_list = history[0].get('from')
        old_bc_address = ''
        for address in from_list:
            if old_bc_address == '':
                old_bc_address = address
            else:
                if old_bc_address != address:
                    verified = False

        # If it's verified that there's only one from address in the history transaction of the new address, the correctness
        # of the transactions from the old_address is checked.
        if verified == True:
            old_history = history_testnet(old_bc_address)
            # ToDo: Think how to verify he correctness of the transactions from the old bitcoin address. We could calculate the amount of bitcoins
            # ToDo: that came from the DCS, and check if it is lower than the reputation transferred, or directly check the reputation value stored in the DCS
            # ToDo: DB (actually not implemented) and check that the amount transferred is lower than that one.

    response = {'verified': verified}
    return jsonify(response)

if __name__ == '__main__':
    app.run(port=5001)
