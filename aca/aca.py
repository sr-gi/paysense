__author__ = 'sdelgado'

from flask import Flask, request
from base64 import b64encode
from os import path
import time
from M2Crypto import X509, EC, EVP, BIO, ASN1

app = Flask(__name__)

ACA_CERT = 'ACA/cacert.pem'
ACA_KEY = 'ACA/private/cakey.pem'
CS_CERTS_PATH = 'ACA/newcerts/'


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

    print cert.verify(ca_cert.get_pubkey())

    # Store certificate
    store_certificate(cert, bitcoin_address)


def generate_keys(bitcoin_address):

    # Generate the elliptic curve and the keys
    ec = EC.gen_params(EC.NID_secp256k1)
    ec.gen_key()

    # Save both keys
    ec.save_key(bitcoin_address + '_key.pem', None)
    ec.save_pub_key(bitcoin_address + '_public_key.pem')

    # Generate a Pkey object to store the EC keys
    mem = BIO.MemoryBuffer()
    ec.save_pub_key_bio(mem)
    ec.save_key_bio(mem, None)
    pk = EVP.load_key_bio(mem)

    return pk


def get_cs_certificate(bitcoin_address):
    if path.exists(CS_CERTS_PATH + bitcoin_address + '.pem'):
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
    bitcoin_address = request.args.get('bitcoin_address')
    # ToDo: This must be changed. The generation of the keys should be done by the CS and it should send a CSR to be signed by the CA.
    # ToDo: Create a CSR could be challenging for a Android device. A work around could be send the public key and the bitcoin address to the CA an let it generate the complete certificate
    pk = generate_keys(bitcoin_address)

    # Generate the digital certificate
    certificate = generate_certificate(pk, bitcoin_address)
    return certificate

if __name__ == '__main__':
    app.run(port=5001)
    #bitcoin_address = "1Dn9CJJgt8fqzTdDiPvcRiA5cmnPNkx3Wxa"
    #pk = generate_keys(bitcoin_address)
    #generate_certificate(pk, bitcoin_address)
