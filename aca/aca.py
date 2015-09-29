from base64 import b64encode, b64decode
from os import path
from os import remove
import time
import ConfigParser

from flask import Flask, request, jsonify
from M2Crypto import X509, EC, EVP, BIO, ASN1

from bitcointools import public_key_to_bc_address, get_pub_key_hex, history_testnet

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


# Generates a JSon-like response with the public and private key, and the certificate of the requester CS.
# ToDO: CHANGE THIS FUNCTION
# Once the CS registration is done using blind signatures, the CS should send a CSR to the ACA. The ACA will response
# only with the generated certificate, both keys will be in possession of the CS instead of the ACA.
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


# Stores a certificate in the certificates path
# @certificate is the certificate object with all the necessary information
# @bitcoin_address is the name that will be used to store this certificate. This name matches with the bitcoin address
# of the CS.
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


# Generates a certificate for a requester CS
# @pkey is an object that represents the CS public key (elliptic curve key).
# @bitcoin_address is the identifier of the CS, that will be placed in the CN of the certificate
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


# Generates a elliptic curve key pair that will be sent lately to the CS.
# ToDO: DELETE THIS FUNCTION
# This function should be deleted once the registration is done using blind signatures, the key pair will be already
# in possession of the CS.
def generate_keys():
    # Generate the elliptic curve and the keys
    ec = EC.gen_params(EC.NID_secp256k1)
    ec.gen_key()

    # Generate a pkey object to store the EC keys
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

    return pk, bitcoin_address


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
        response = "Invalid parameter.\n"
    else:
        # Look for the digital certificate in the existing ones
        certificate = get_cs_certificate(bitcoin_address)
        if certificate is not None:
            response = b64encode(certificate)
        else:
            response = "There's no digital certificate for the given bc address"

    return response


# Serves the ACA certificate requests
@app.route('/get_ca_cert', methods=['GET'])
def api_get_ca_pem():
    certificate = get_ca_certificate()
    return b64encode(certificate)


# Serves the registration requests from the CS
# ToDO: CHANGE THIS FUNCTION
# This is a workaround, in this first version the ACA generates either the keys and the certificate.
# Once the registration is done using blind signatures, the bitcoin address and the public key should be
# obtained with the request
@app.route('/sign_in', methods=['GET'])
def api_sign_in():
    # Get the bitcoin_address from the url
    # bitcoin_address = request.args.get('bitcoin_address')
    # pk = generate_keys(bitcoin_address)
    pk, bitcoin_address = generate_keys()

    # Generate the digital certificate
    generate_certificate(pk, bitcoin_address)

    # Send response to the CS
    response = generate_response(bitcoin_address)

    return jsonify(response)


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
        if verified == True:
            old_history = history_testnet(old_bc_address)
            # ToDo: Think how to verify the correctness of the transactions from the old bitcoin address. We could calculate the amount of bitcoins
            # ToDo: that came from the DCS, and check if it is lower than the reputation transferred, or directly check the reputation value stored in the DCS
            # ToDo: DB (actually not implemented) and check that the amount transferred is lower than that one.

    response = {'verified': verified}
    return jsonify(response)


def test():

    CSR = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI3VENDQVpNQ0FRQXdDZ1lJS29aSXpqMEVBd0l3Z1lZeEN6QUpCZ05WQkFZVEFrTlVNUkl3RUFZRFZRUUkKREFsQ1lYSmpaV3h2Ym1FeEV6QVJCZ05WQkFjTUNrSmxiR3hoZEdWeWNtRXhFVEFQQmdOVkJBb01DRkJoZVZObApibk5sTVF3d0NnWURWUVFMREFOQlEwRXhEREFLQmdOVkJBTU1BMEZEUVRFZk1CMEdDU3FHU0liM0RRRUpBUllRCllXTmhRR1JsYVdNdWRXRmlMbU5oZERBZUZ3MHhOVEE1TWpreE5UQXhNak5hRncweE5qQTVNamd4TlRBeE1qTmEKTUlHQU1Rc3dDUVlEVlFRR0V3SkRWREVTTUJBR0ExVUVDQXdKUW1GeVkyVnNiMjVoTVJNd0VRWURWUVFIREFwQwpaV3hzWVhSbGNuSmhNUXd3Q2dZRFZRUUtEQU5WUVVJeERUQUxCZ05WQkFzTUJFUkZTVU14S3pBcEJnTlZCQU1NCkltMXFXa280YjNaVldFdDJOa1EwUjFCTk9URldjVFZ6UjFjNVFXNW9VMjgwWkV3d1ZqQVFCZ2NxaGtqT1BRSUIKQmdVcmdRUUFDZ05DQUFSVjh2OVRzdm0xQ3VxeVNJSEROdDZpRm1ZdWRWZ0IxaHVhQzhHZU1FK05BejZRaTJQQgo1KzcyQno4QlptSGlxNnllSG5sRG9JRWcvQkxuTG0zYkJUV2xNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJRGtzClVXU1NqVHE5bFBrZFgwZDhhK2JMM1piM2c1Vzd5ZGlrZTE1WEJHOGtBaUVBaHFvQVV1cHhweDRUdzlpWFZhRHEKUWE5Mzhsb0poenAvbVZ6RTZMNllob1U9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
    cert = X509.load_cert_string(b64decode(CSR))

    # Load ACA private key
    ca_pkey = EVP.load_key(ACA_KEY)

    cert.sign(ca_pkey, md='sha256')

    print cert.as_text()

if __name__ == '__main__':
    #app.run(port=5001)
    test()
