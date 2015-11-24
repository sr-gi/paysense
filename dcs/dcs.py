import urllib2
import ConfigParser
from base64 import b64decode
from M2Crypto import X509, EC
from flask import Flask, request, json

from utils.bitcoin.transactions import reputation_transfer

__author__ = 'sdelgado'

S_KEY = 'private/paysense.key'
CERT = 'paysense.crt'
DEFAULT_AMOUNT = 1000

# Configuration file data loading
config = ConfigParser.ConfigParser()
config.read("paysense.conf")

BTC_ADDRESS = config.get("BitcoinAddresses", "DCS", )
ACA = config.get("Servers", "ACA", )


# Gets the CS certificate from the ACA in pem format
# @bitcoin_address is the bitcoin address that identifies the CS
# @return CS certificate in pem format
def get_cs_pem_data(bitcoin_address):
    try:
        response = urllib2.urlopen(ACA + '/get_cs_cert?bitcoin_address=' + bitcoin_address)
        response = b64decode(response.read())
    except urllib2.URLError as e:
        response = e

    return response


# Gets the ACA certificate in pem format
# @return ACA certificate in pem format
def get_ca_pem_data():
    try:
        response = urllib2.urlopen(ACA + '/get_ca_cert')
        response = b64decode(response.read())
    except urllib2.URLError as e:
        response = e

    return response


# Verifies the CS and the ACA signatures from a received sensing data
# @message is the sensed data itself
# @signature is the signature of the data, performed by the CS
# @bitcoin_address is the bitcoin address that identifies the CS
# @cs_pem_data is an optional parameter that represents the certificate of the CS. If no certificate is provided,
# the function will request one to the ACA using the @bitcoin_address as a parameter
def verify_data(message, signature, bitcoin_address, cs_pem_data=None):
    if cs_pem_data is None:
        # Get CS from the ACA (pem data base64 encoded)
        cs_pem_data = get_cs_pem_data(bitcoin_address)

    # Get CA certificates from the ACA (pem data base64 encoded)
    ca_pem_data = get_ca_pem_data()

    # If the data could not be obtained from the server
    if type(ca_pem_data) is urllib2.URLError or type(cs_pem_data) is urllib2.URLError:
        ca_verify = cs_verify = False
    else:
        # Store received data in X509 structure
        cs_certificate = X509.load_cert_string(cs_pem_data)
        ca_certificate = X509.load_cert_string(ca_pem_data)

        # Get CS public key from received data
        cs_public_key = EC.pub_key_from_der(cs_certificate.get_pubkey().as_der())

        # Verify CA signature in CS certificate and CS signature in data sent
        ca_verify = cs_certificate.verify(ca_certificate.get_pubkey())
        cs_verify = cs_public_key.verify_dsa_asn1(message, signature)

    return {'ca': ca_verify, 'cs': cs_verify}


def pay_to_cs(bitcoin_address, amount=None, used_txs=None):
    if amount is None:
        amount = DEFAULT_AMOUNT

    tx_hash, used_txs = reputation_transfer(S_KEY, BTC_ADDRESS, bitcoin_address, amount, fee=DEFAULT_AMOUNT, used_txs=used_txs)

    return tx_hash, used_txs


############################
#       WEB INTERFACE      #
############################

app = Flask(__name__)


# Serves the sensed data recollection from the CSs
@app.route('/', methods=['POST'])
def api_receive_data():
    if request.headers['Content-Type'] == 'application/json':
        message = str(request.json.get("message"))
        signature = str(request.json.get("signature"))
        bitcoin_address = request.json.get("bitcoin_address")
        cs_pem_data = request.json.get("cs_pem_data")
        if message is not None and signature is not None and bitcoin_address is not None:
            if cs_pem_data is None:
                verify = verify_data(message, b64decode(signature), bitcoin_address)
            else:
                verify = verify_data(message, b64decode(signature), bitcoin_address, b64decode(cs_pem_data))

            if verify['ca'] & verify['cs']:
                response = "Sensing data correctly verified"
                # ToDO: Data should be validated before performing the payment for the sensing.
                pay_to_cs(bitcoin_address)

            else:
                response = json.dumps({'data': "Sensing data can't be verified\n"}), 500
        else:
            response = json.dumps({'data': "Some data is missing\n"}), 500

    else:
        response = json.dumps({'data': "Wrong data format\n"}), 500

    return response


if __name__ == '__main__':
    app.run()



