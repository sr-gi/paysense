__author__ = 'sdelgado'

from pycoin import ecdsa
from OpenSSL import crypto
from flask import Flask
from flask import request
app = Flask(__name__)


def get_pem_data(bitcoin_address):
    f = open(bitcoin_address + '.pem', 'r')
    pem_data = f.read()

    return pem_data


def get_digital_certificate(pem_data):
    # DCS should contact either with the CS or with the ACA to get the digital cert.
    # Temporally digital cert.

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)

    return certificate


def get_public_key(pem_data):

    data = pem_data[pem_data.find('pub:') + 4:pem_data.find('ASN1')]
    data = data.replace(" ", "")
    data = data.replace(":", "")
    public_key = data.replace("\n", "")
    return public_key


def verify_signature(public_key, message, signature):

    x = int(public_key[2:66], 16)
    y = int(public_key[66:], 16)

    v = ecdsa.verify(ecdsa.generator_secp256k1, (x, y), message, signature)

    if v:
        print 'Message signature verified'
    else:
        print 'Wrong message signature'

    assert v


def main(message, signature, bitcoin_address):

    cs_pem_data = get_pem_data(bitcoin_address)
    ca_pem_data = get_pem_data('cacert')

    cs_certificate = get_digital_certificate(cs_pem_data)
    ca_certificate = get_digital_certificate(ca_pem_data)

    # VERIFY CA SIGNATURE

    cs_public_key = get_public_key(cs_pem_data)
    verify_signature(cs_public_key, message, signature)

@app.route('/', methods=['POST'])
def api_receive_data():

    if request.headers['Content-Type'] == 'application/json':
        # IF NO CERTIFICATE SENT
        main(request.json["message"], request.json["signature"], request.json["bitcoin_address"])
        return "Sensing data received"
        # IF CERTIFICATE SENT

if __name__ == '__main__':
    app.run()

