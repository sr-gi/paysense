__author__ = 'sdelgado'

from M2Crypto import X509, EC
from flask import Flask, request
import urllib2
from base64 import b64decode
from bitcointransactions import single_payment
from bitcointools import bc_address_from_cert

S_KEY = 'private/paysense.key'
CERT = 'paysense.crt'
DEFAULT_AMOUNT = 1000


# Gets the CS certificate from the ACA in pem format
# @bitcoin_address is the bitcoin address that identifies the CS
# @return CS certificate in pem format
def get_cs_pem_data(bitcoin_address):
    response = urllib2.urlopen('http://127.0.0.1:5001/get_cs_cert?bitcoin_address=' + bitcoin_address)
    pem_data = b64decode(response.read())

    return pem_data

# Gets the ACA certificate in pem format
# @return ACA certificate in pem format
def get_ca_pem_data():
    response = urllib2.urlopen('http://127.0.0.1:5001/get_ca_cert')
    pem_data = b64decode(response.read())

    return pem_data


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

    # Store received data in X509 structure
    cs_certificate = X509.load_cert_string(cs_pem_data)
    ca_certificate = X509.load_cert_string(ca_pem_data)

    # Get CS public key from received data
    cs_public_key = EC.pub_key_from_der(cs_certificate.get_pubkey().as_der())

    # Verify CA signature in CS certificate and CS signature in data sent
    ca_verify = cs_certificate.verify(ca_certificate.get_pubkey())
    cs_verify = cs_public_key.verify_dsa_asn1(message, signature)

    return {'ca': ca_verify, 'cs': cs_verify}

def pay_to_cs(bitcoin_address, amount=None):
    if amount is None:
        amount = DEFAULT_AMOUNT
    dcs_address = bc_address_from_cert(CERT)
    single_payment(S_KEY, dcs_address, bitcoin_address, amount)



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
        print type(message), type(signature), type(bitcoin_address)
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
                response = "Sensing data can't be verified"
        else:
            response = "Some data is missing"

    else:
        response = "Wrong data format"

    return response


if __name__ == '__main__':
    app.run()
