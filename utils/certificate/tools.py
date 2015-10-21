from pyasn1.codec.der import encoder
from hashlib import sha256

__author__ = 'sdelgado'


def certificate_hashing(asn1_cert, algorithm='sha256'):

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


