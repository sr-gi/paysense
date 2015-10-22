from pyasn1.codec.der import encoder, decoder
from pyasn1_modules.rfc2459 import Certificate
from Crypto.PublicKey import RSA
from hashlib import sha256

__author__ = 'sdelgado'


def certificate_hashing(cert_der, algorithm='sha256'):
    """ Performs the hash of a provided X509 certificate.

    :param cert_der: x509 certificate in der format.
    :param algorithm: hashing algorithm. Sha256 will be used as default.
    :return: The hash of the certificate performed using the provided hashing function.
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

    :param cert_der: input certificate (in der format).
    :param blinded_hash: input blinded hash to be checked
    :param r: blinding factor used to perform the blind hash.
    :param ca_cert: CA cert. It will be used to extract the public key and perform the hash blinding.
    :return: True if the hashes match. False otherwise.
    """
    pk = RSA.importKey(ca_cert.get_pubkey().as_der())

    cert_hash = certificate_hashing(cert_der)

    # Check that the provided blind signatures match with the calculated ones
    if pk.blind(cert_hash, r) == blinded_hash:
        response = True
    else:
        response = False

    return response


