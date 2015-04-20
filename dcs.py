__author__ = 'sdelgado'

from cryptography import x509
from pycoin import ecdsa


def receive_message():
    # Temporally secret exponent. This exponent represents the private key of an imaginary CS, normally it can't be known by the DCS
    secret_exponent = int("72a9c01b36d19e32a4cad0e2ed834e0928a2f100a89d7f01e3d53ff3bf36379f", 16)

    # Temporally message. Message should be given with the bitcoin_address from the CS each time data will be validated.
    message = 855646545641
    # Temporally signature. Signature should be given with the bitcoin_address from the CS each time data will be validated.
    signature = ecdsa.sign(ecdsa.generator_secp256k1, secret_exponent, message)
    # Temporally bitcoin address
    bitcoin_address = ""

    return {"message": message, "signature": signature, "bitcoin_address": bitcoin_address}


def get_digital_certificate(public_key):
    # DCS should contact either with the CS or with the ACA to get the digital cert.
    # Temporally digital cert.
    certificate = x509.Certificate

    return certificate


def get_public_key(certificate):
    # return certificate.public_key
    # Temporally public key. Public key should be extracted from the digital certificate obtained either from the CS or from the ACA
    public_key = "049d6b3aa77d1b3e9d82bbd2c68ba392f534d8b4258901322e60afa45d1f9f16e63fb2d231e3204ef4aedd183db8a646f02bc00abc620b3ea5f98fce8c1f9c8894"
    return public_key


def verify_signature(bitcoin_address, message, signature):

    # Public key should be get from the bitcoin address, still under construction
    certificate = get_digital_certificate(bitcoin_address)
    public_key = get_public_key(certificate)

    x = int(public_key[2:66], 16)
    y = int(public_key[66:], 16)

    v = ecdsa.verify(ecdsa.generator_secp256k1, (x, y), message, signature)

    assert v


def main():
    data = receive_message()
    get_digital_certificate("")
    verify_signature(data["bitcoin_address"], data["message"], data["signature"])

if __name__ == "__main__":
    main()

