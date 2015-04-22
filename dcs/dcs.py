__author__ = 'sdelgado'

from pycoin import ecdsa
from M2Crypto import X509
from flask import Flask, request
import urllib2
from base64 import b64decode
app = Flask(__name__)


def get_cs_pem_data(bitcoin_address):
    response = urllib2.urlopen('http://127.0.0.1:5001?bitcoin_address=' + bitcoin_address)
    pem_data = b64decode(response.read())

    return pem_data


def get_ca_pem_data():
    response = urllib2.urlopen('http://127.0.0.1:5001/CA')
    pem_data = b64decode(response.read())

    return pem_data


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

    return v


def verify_data(message, signature, bitcoin_address, cs_pem_data=None):

    if cs_pem_data is None:
        # Get CS from the ACA (pem data base64 encoded)
        cs_pem_data = get_cs_pem_data(bitcoin_address)

    # Get CA certificates from the ACA (pem data base64 encoded)
    ca_pem_data = get_ca_pem_data()

    # Get CS public key from received data
    cs_public_key = get_public_key(cs_pem_data)

    # Store received data in X509 structure
    cs_certificate = X509.load_cert_string(cs_pem_data)
    ca_certificate = X509.load_cert_string(ca_pem_data)

    # Verify CA signature in CS certificate and CS signature in data sent
    ca_verify = cs_certificate.verify(ca_certificate.get_pubkey())
    cs_verify = verify_signature(cs_public_key, message, signature)

    return {'ca': ca_verify, 'cs': cs_verify}

@app.route('/', methods=['POST'])
def api_receive_data():

    if request.headers['Content-Type'] == 'application/json':
        message = request.json.get("message")
        signature = request.json.get("signature")
        bitcoin_address = request.json.get("bitcoin_address")
        cs_pem_data = request.json.get("cs_pem_data")
        if message is not None and signature is not None and bitcoin_address is not None:
            if cs_pem_data is None:
                verify = verify_data(message, signature, bitcoin_address)
            else:
                verify = verify_data(message, signature, bitcoin_address,  b64decode(cs_pem_data))

            if verify['ca'] & verify['cs']:
                response = "Sensing data correctly verified"
            else:
                response = "Sensing data can't be verified"
        else:
            response = "Some data is left"

    else:
        response = "Wrong data format"

    return response

if __name__ == '__main__':
    app.run()
    #response = verify_data(34512343291048, (33613386346233360721867108789613622200364938080444254352397512204642261745507L, 9258081509095521074544767295719658866617273164565212740614783596151411291495L), '1Dn9CJJgt8fqzTdDiPvcRiA5cmnPNkx3Wx')
    #print response
