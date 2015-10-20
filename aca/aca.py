from base64 import b64encode, b64decode
from os import path
import ConfigParser

from flask import Flask, request, jsonify, json
from M2Crypto import X509
from pyasn1_modules.rfc2459 import Certificate
from pyasn1.codec.der import decoder
from Crypto.PublicKey import RSA
from random import randint
from certificatetools import certificate_hashing

from bitcointools import history_testnet

__author__ = 'sdelgado'

############################
#     GLOBAL VARIABLES     #
############################

# Locals paths to the ACA files
ACA_CERT = 'paysense.crt'
ACA_KEY = 'private/paysense.key'
CS_CERTS_PATH = 'certs/'

# Bitcoin address of the DCS (globally known)
config = ConfigParser.ConfigParser()
config.read("paysense.conf")

DCS_BC_ADDRESS = config.get("BitcoinAddresses", "DCS", )


############################
#        FUNCTIONS         #
############################

# Checks the correctness of the certificates provided by the CS
def check_certificate_data(certs):
    return True


# Computes the blind hashes of the provided certificates and checks that they match with the provided blinded hashes
# @certs_der are the provided certificates in der format
# @rands are the provided blinding factors
def check_blind_hashes(certs_der, rands):
    response = True

    # Load key
    f = open(ACA_CERT)
    aca_cert_text = f.read()
    f.close()
    aca_cert = X509.load_cert_string(aca_cert_text)
    pk = RSA.importKey(aca_cert.get_pubkey().as_der())

    for i in range(len(certs_der)):
        if i is not r:
            print r
            asn1_cert = decoder.decode(certs_der[i], asn1Spec=Certificate())[0]
            cert_hash = certificate_hashing(asn1_cert)

            # Check that the provided blind signatures match with the calculated ones
            if pk.blind(cert_hash, rands[i]) != blinded_hashes[i]:
                response = False
                break
    return response


# Checks if a certificate exists in the certificate directory
# @bitcoin_address is the name of the certificate to look for
# @return true/false depending on if the file exists or not
def check_certificate(bitcoin_address):
    return path.exists(CS_CERTS_PATH + bitcoin_address + '.pem')


# Checks the payers in the transaction history of a bitcoin address
# ToDo: FIX THIS FUNCTION
# This function should be changed, makes no sense how it's done now.
# It should validate that the payments come from the DCS or from a previously certified CS (just the first payment).
# To be efficient the blockchain should be analyzed only after the certification date of the CS.
def check_payers(history, expected_payer=None):
    validation = True
    if expected_payer is None:
        expected_payer = DCS_BC_ADDRESS
    if len(history) == 0:
        validation = False
    for i in range(len(history)):
        payer = history[i].get('from')
        if payer is not expected_payer:
            validation = False

    return validation


# Stores a certificate in the certificates path
# @certificate is a String representation of the certificate
# @bitcoin_address is the name that will be used to store this certificate. This name matches with the bitcoin address
# of the CS.
def store_certificate(certificate, bitcoin_address):

    # ca_pkey = EVP.load_key(ACA_KEY)
    # cert = X509.load_cert_string(certificate)
    #
    #
    # if cert.verify(ca_pkey):
    #     f = open(CS_CERTS_PATH + bitcoin_address + '.pem', 'w')
    #     f.write(certificate)
    #     f.close()
    #     response = "OK"
    # else:
    #     response = "Bad Certificate"

    # Load ACA cert and public key
    aca_cert = X509.load_cert(ACA_CERT)
    pk = RSA.importKey(aca_cert.get_pubkey().as_der())

    # Obtain the TBS certificate
    cert = X509.load_cert_string(certificate)

    asn1_cert = decoder.decode(cert.as_der(), asn1Spec=Certificate())[0]

    cert_hash = certificate_hashing(asn1_cert)

    # tbs = asn1_cert.getComponentByName("tbsCertificate")
    #
    # # Calculate the certificate hash
    # tbs_der = encoder.encode(tbs)
    # digest = sha256()
    # digest.update(tbs_der)
    # cert_hash = digest.digest()

    # Extract the certificate signature
    signature_bin = asn1_cert.getComponentByName("signatureValue")

    # Parse the signature
    signature_str = ""
    for i in signature_bin:
        signature_str += str(i)
    signature = long(signature_str, 2)

    # Check the parsed signature matches with the signature ob the obtained hash
    if pk.verify(cert_hash, [signature, 0]):
        f = open(CS_CERTS_PATH + bitcoin_address + '.pem', 'w')
        f.write(certificate)
        f.close()
        response = "OK"
    else:
        response = json.dumps({'data': "Bad certificate\n"}), 500

    return response


# Returns a CS certificate
# @bitcoin_address is the CS pseudonym. It is used to look for the specific file name in the certificates directory.
# @return the requested certificate
def get_cs_certificate(bitcoin_address):
    if check_certificate(bitcoin_address):
        f = open(CS_CERTS_PATH + bitcoin_address + '.pem')
        certificate = f.read()
        f.close()
    else:
        certificate = None

    return certificate


# Returns the ACA certificate
# @return the ACA certificate
def get_ca_certificate():
    f = open(ACA_CERT)
    certificate = f.read()
    f.close()

    return certificate


############################
#       WEB INTERFACE      #
############################

app = Flask(__name__)


# Serves the CS certificate requests
# ToDo: Check if the requests should be restricted
@app.route('/get_cs_cert', methods=['GET'])
def api_get_cs_pem():
    # Get the bitcoin_address from the url
    bitcoin_address = request.args.get('bitcoin_address')
    if bitcoin_address is None:
        response = json.dumps({'data': "Invalid parameter\n"}), 500
    else:
        # Look for the digital certificate in the existing ones
        certificate = get_cs_certificate(bitcoin_address)
        if certificate is not None:
            response = b64encode(certificate)
        else:
            response = json.dumps({'data': "There's no digital certificate for the given bc address\n"}), 500

    return response


# Serves the ACA certificate requests
@app.route('/get_ca_cert', methods=['GET'])
def api_get_ca_pem():
    certificate = get_ca_certificate()
    return b64encode(certificate)


# Serves the registration requests from the CS
@app.route('/sign_in', methods=['POST'])
def api_sign_in():
    response = json.dumps({'data': "Wrong request\n"}), 500

    if request.headers['Content-Type'] == 'application/json':
        step = request.json.get("step")
        if step == 1:
            message = str(request.json.get("cert_hashes"))

            global blinded_hashes
            blinded_hashes = eval(b64decode(message))

            global r
            r = randint(0, 99)

            response = b64encode(str(r))
        elif step == 2:
            message = b64decode(str(request.json.get("certs")))
            certs_der = eval(message)

            message = request.json.get("rands")
            rands = eval(message)

            if check_certificate_data(certs_der) and check_blind_hashes(certs_der, rands):
                f = open(ACA_KEY, "r")
                sk_string = f.read()
                f.close()

                sk = RSA.importKey(sk_string)
                signature = sk.sign(blinded_hashes[r], 1)[0]

                response = b64encode(str(signature))
            else:
                response = json.dumps({'data': "Provided certificates contain wrong data\n"}), 500

    return response


# Serves the certificate storage received from the CSs
@app.route('/store_certificate', methods=['POST'])
def api_store_cert():
    if request.headers['Content-Type'] == 'application/json':
        certificate = str(request.json.get("certificate"))
        bitcoin_address = str(request.json.get("bitcoin_address"))

        response = store_certificate(certificate, bitcoin_address)
    else:
        response = "Bad request"
    return response


# Serves the reputation exchange requests from the CSs
# ToDo: CHANGE THIS FUNCTION
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
        # If there's only one transaction, the list of 'from addresses' is extracted from the history and is verified that
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
        if verified:
            old_history = history_testnet(old_bc_address)
            # ToDo: Think how to verify the correctness of the transactions from the old bitcoin address. We could calculate the amount of bitcoins
            # ToDo: that came from the DCS, and check if it is lower than the reputation transferred, or directly check the reputation value stored in the DCS
            # ToDo: DB (actually not implemented) and check that the amount transferred is lower than that one.

    response = {'verified': verified}
    return jsonify(response)


if __name__ == '__main__':
    app.run(port=5001)
