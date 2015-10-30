from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc2459 import Certificate
from Crypto.PublicKey import RSA
from hashlib import sha256

__author__ = 'sdelgado'


def certificate_hashing(cert_der, algorithm='sha256'):
    """ Performs the hash of a provided X509 certificate.

    :param cert_der: x509 certificate.
    :type cert_der: binary DER
    :param algorithm: hashing algorithm. Sha256 will be used as default.
    :type algorithm: str
    :return: The hash of the certificate performed using the provided hashing function.
    :rtype: binary
    """

    asn1_cert = decoder.decode(cert_der, asn1Spec=Certificate())[0]
    tbs = asn1_cert.getComponentByName("tbsCertificate")

    # Calculate the certificate hash
    tbs_der = encoder.encode(tbs)
    if algorithm == 'sha256':
        digest = sha256()
    else:
        # ToDo: Check if we should include more hashing algorithms
        return "Algorithm not supported"
    digest.update(tbs_der)
    cert_hash = digest.digest()

    return cert_hash


def check_blind_hash(cert_der, blinded_hash, r, ca_cert):
    """ Compute the blind hash of the provided certificate and check if it match with the provided blinded hash

    :param cert_der: input certificate.
    :type cert_der: binary DER
    :param blinded_hash: input blinded hash to be checked.
    :type blinded_hash: binary
    :param r: blinding factor used to perform the blind hash.
    :type r: long
    :param ca_cert: CA cert. It will be used to extract the public key and perform the hash blinding.
    :type ca_cert: M2Crypto.X509
    :return: True if the hashes match, False otherwise.
    :rtype: bool
    """
    pk = RSA.importKey(ca_cert.get_pubkey().as_der())

    cert_hash = certificate_hashing(cert_der)

    # Check that the provided blind signatures match with the calculated ones
    if pk.blind(cert_hash, r) == blinded_hash:
        response = True
    else:
        response = False

    return response


def store_certificate(certificate, filename='paysense'):
    """ Stores a certificate in a human readable format

    :param certificate: certificate to be stored
    :type certificate: binary DER
    :param filename: name or system path (including name) where the certificate will be stored (without extension)
    :type filename: str
    :return: None
    """
    # Save the pem data into the pem file
    certificate.save_pem(filename + '.crt')

    # In order to write the human readable certificate before the encoded data we should load the data just stored
    # and append at the end of the file.
    f = open(filename + '.crt', 'r')
    data = f.read()
    f.close()
    f = open(filename + '.crt', 'w')
    f.write(certificate.as_text())
    f.write(data)
    f.close()
