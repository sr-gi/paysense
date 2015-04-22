__author__ = 'sdelgado'

from pycoin import ecdsa
from M2Crypto import X509
from flask import Flask
from flask import request

app = Flask(__name__)


def get_pem_data(bitcoin_address):
    f = open(bitcoin_address, 'r')
    pem_data = f.read()

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


def main(message, signature, bitcoin_address):

    # Get CS public key from .pem file
    cs_pem_data = get_pem_data(bitcoin_address + '.pem')
    cs_public_key = get_public_key(cs_pem_data)

    # Lad both CS and CA certificates
    cs_certificate = X509.load_cert(bitcoin_address + '.pem')
    ca_certificate = X509.load_cert('cacert.pem')

    # Verify CA signature in CS certificate and CS signature in data sent
    ca_verify = cs_certificate.verify(ca_certificate.get_pubkey())
    cs_verify = verify_signature(cs_public_key, message, signature)

    return {'ca': ca_verify, 'cs': cs_verify}

@app.route('/', methods=['POST'])
def api_receive_data():

    if request.headers['Content-Type'] == 'application/json':
        # IF NO CERTIFICATE SENT
        verify = main(request.json["message"], request.json["signature"], request.json["bitcoin_address"])
        # IF CERTIFICATE SENT
        # bla bla bla

        if verify['ca'] & verify['cs']:
            return "Sensing data correctly verified.\n"
        else:
            return "Sensing data can't be verified.\n"

    else:
        return "Wrong data format.\n"

if __name__ == '__main__':
    app.run()
    #main(34512343291048, (33613386346233360721867108789613622200364938080444254352397512204642261745507L, 9258081509095521074544767295719658866617273164565212740614783596151411291495L), '1Dn9CJJgt8fqzTdDiPvcRiA5cmnPNkx3Wx')

