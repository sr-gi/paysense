__author__ = 'sdelgado'

from flask import Flask, request
from base64 import b64encode
from os import path
app = Flask(__name__)


def get_cs_certificate(bitcoin_address):
    if path.exists('./ACA/newcerts/' + bitcoin_address + '.pem'):
        f = open('./ACA/newcerts/' + bitcoin_address + '.pem')
        certificate = f.read()
        f.close()
    else:
        certificate = None

    return certificate

def get_ca_certificate():
    f = open('./ACA/cacert.pem')
    certificate = f.read()
    f.close()

    return certificate

@app.route('/', methods=['GET'])
def api_get_cs_pem():
    bitcoin_address = request.args.get('bitcoin_address')
    if bitcoin_address is None:
        response = "Invalid parameter.\n"
    else:
        certificate = get_cs_certificate(bitcoin_address)
        if certificate is not None:
            response = b64encode(certificate)
        else:
            response = "There's no digital certificate for the given bc address"

    return response

@app.route('/CA', methods=['GET'])
def api_get_ca_pem():
    certificate = get_ca_certificate()
    return b64encode(certificate)


if __name__ == '__main__':
    app.run(port=5001)