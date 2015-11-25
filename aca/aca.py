# Copyright (c) <2015> <Sergi Delgado Segura>
# Distributed under the BSD software license, see the accompanying file LICENSE

from base64 import b64encode, b64decode
from os import path
import ConfigParser
from random import randint
from flask import Flask, request, jsonify, json
from M2Crypto import X509, urllib2, EVP
from pyasn1_modules.rfc2459 import Certificate
from pyasn1_modules.rfc2314 import Signature
from pyasn1.codec.der import decoder, encoder
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

from utils.certificate.tools import certificate_hashing, check_blind_hash, check_certificate, store_certificate as utils_store_certificate
from utils.bitcoin.transactions import history_testnet, check_txs_source

__author__ = 'sdelgado'

############################
#     GLOBAL VARIABLES     #
############################

# Configuration file data loading
config = ConfigParser.ConfigParser()
config.read("paysense.conf")

DCS_BTC_ADDRESS = config.get("BitcoinAddresses", "DCS", )
CERT_COUNT = int(config.get("Misc", "CertCount"))

# Locals paths to the ACA files
ACA_CERT = config.get("Paths", "CERT", )
ACA_KEY = config.get("Paths", "KEY", )
CS_CERTS_PATH = config.get("Paths", "CERTS_PATH", )

############################
#        FUNCTIONS         #
############################


# Checks the correctness of the certificates provided by the CS
def check_certificate_data(certificates):
    """
    Checks the correctness of the certificates provided by the CS.
    :param certificates: the provided certificates.
    :type certificates: DER str list
    :return: True if the certificates are correct, False otherwise.
    :rtype: bool
    """
    # ToDo: Decide witch fields of the certificate have to be checked and how
    return True


def check_hashes_validity(certificates, rands):
    """ Check if the provided blind hashes matches with the blinded hashes of the provided certificates.

    :param certificates: the provided certificates.
    :type certificates: DER str list
    :param rands: the provided blinding factors.
    :return: True if all the hashes match. False otherwise.
    :rtype: bool
    """
    response = True

    # Load key
    f = open(ACA_CERT)
    aca_cert_text = f.read()
    f.close()
    aca_cert = X509.load_cert_string(aca_cert_text)

    for i in range(len(certificates)):
        if i is not r:
            validity = check_blind_hash(certificates[i], blinded_hashes[i], rands[i], aca_cert)

            # Check that the provided blind signatures match with the calculated ones
            if not validity:
                response = validity
                break
    return response


# Stores a certificate in the certificates path
# @certificate is a DER str representation of the certificate
# @bitcoin_address is the name that will be used to store this certificate. This name matches with the bitcoin address
# of the CS.
def store_certificate(certificate, bitcoin_address):
    # Load ACA cert and public key
    aca_cert = X509.load_cert(ACA_CERT)
    pk = RSA.importKey(aca_cert.get_pubkey().as_der())

    # Obtain the TBS certificate
    cert_hash = certificate_hashing(certificate)
    asn1_cert = decoder.decode(certificate, asn1Spec=Certificate())[0]

    # Extract the certificate signature
    signature_bin = asn1_cert.getComponentByName("signatureValue")

    # Parse the signature
    signature_str = ""
    for i in signature_bin:
        signature_str += str(i)
    signature = long(signature_str, 2)

    # Check the parsed signature matches with the signature of the obtained hash
    if pk.verify(cert_hash, [signature, 0]):
        utils_store_certificate(certificate, CS_CERTS_PATH + bitcoin_address, '.pem')
        response = "Certificate correctly stored"
    else:
        response = json.dumps({'data': "Bad certificate\n"}), 500

    return response


# Returns a CS certificate
# @bitcoin_address is the CS pseudonym. It is used to look for the specific file name in the certificates directory.
# @return the requested certificate
def get_cs_certificate(bitcoin_address):
    if check_certificate(CS_CERTS_PATH, bitcoin_address):
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


@app.route('/get_tor_address', methods=['GET'])
def api_get_tor_address():
    response = urllib2.urlopen("http://127.0.0.1:5002" + '/get_address')
    return response.read()


# Serves the registration requests from the CS
@app.route('/sign_in', methods=['POST'])
def api_sign_in():
    response = json.dumps({'data': "Wrong request\n"}), 500

    if request.headers['Content-Type'] == 'application/json':
        step = request.json.get("step")
        if step == 1:
            message = str(request.json.get("cert_hashes"))

            # ToDo: The user must provide his identity with the cert_hashes. Use that as a id to store the data instead of declaring the following variable as global
            # ToDo: Use a true concurrent server?
            global blinded_hashes
            blinded_hashes = eval(b64decode(message))
            global r
            r = randint(0, CERT_COUNT - 1)

            response = b64encode(str(r))
        elif step == 2:
            message = b64decode(str(request.json.get("certs")))
            certs_der = eval(message)

            message = request.json.get("rands")
            rands = eval(message)

            if check_certificate_data(certs_der) and check_hashes_validity(certs_der, rands):
                f = open(ACA_KEY, "r")
                sk_string = f.read()
                f.close()

                sk = RSA.importKey(sk_string)
                signature = sk.sign(blinded_hashes[r], 1)[0]

                response = b64encode(str(signature))
            else:
                response = json.dumps({'data': "Provided certificates contain wrong data\n"}), 500

    return response


@app.route('/sign_certificate', methods=['POST'])
def api_sign_certificate():
    if request.headers['Content-Type'] == 'application/json':
        certificate = b64decode(str(request.json.get("certificate")))
        bitcoin_address = str(request.json.get("bitcoin_address"))

        # Get the ACA secret key
        f = open(ACA_KEY, "r")
        sk_string = f.read()
        f.close()
        sk = RSA.importKey(sk_string)

        # Get the certificate hash and the asn1 representation of the certificate
        certificate_hash = certificate_hashing(certificate)
        signature = sk.sign(certificate_hash, 1)[0]
        asn1_cert = decoder.decode(certificate, asn1Spec=Certificate())[0]

        # Attach the signature to the certificate
        bin_signature = Signature("'%s'H" % ''.join("%02X" % ord(c) for c in long_to_bytes(signature)))
        asn1_cert.setComponentByName("signatureValue", bin_signature)

        # Store the certificate
        der_cert = encoder.encode(asn1_cert)
        store_certificate(encoder.encode(asn1_cert), bitcoin_address)

        return b64encode(der_cert)


# Serves the certificate storage received from the CSs
@app.route('/store_certificate', methods=['POST'])
def api_store_cert():
    if request.headers['Content-Type'] == 'application/json':
        certificate = b64decode(str(request.json.get("certificate")))
        bitcoin_address = str(request.json.get("bitcoin_address"))

        response = store_certificate(certificate, bitcoin_address)
    else:
        response = json.dumps({'data': "Bad request\n"}), 500
    return response


# Serves the reputation exchange requests from the CSs
@app.route('/reputation_exchange', methods=['GET'])
def api_verify_reputation_exchange():
    # Verifies the correctness of a reputation exchange between a certified bitcoin address and a new one.

    verified = True

    new_btc_addr = request.args.get('new_btc_address')
    history = history_testnet(new_btc_addr)

    # The new address can only have a single transaction, corresponding to the reputation transaction from the old address
    if len(history) != 1:
        verified = False
    else:

        # If there's only one transaction, the list of 'from addresses' is extracted from the history and is verified that
        # all the funds in the input addresses list are verified
        from_list = history[0].get('from')
        check_list = []
        for address in from_list:
            check_list.append(check_txs_source(address, DCS_BTC_ADDRESS, CS_CERTS_PATH))

        if False in check_list:
            verified = False

    response = {'verified': verified}
    return jsonify(response)


if __name__ == '__main__':
    app.run(port=5001)
