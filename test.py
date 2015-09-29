import urllib2
from bitcointools import *
from bitcoin import *
from bitcoinrpc.authproxy import AuthServiceProxy
from M2Crypto import EC, BIO, EVP, ASN1
from base64 import b64encode, b64decode

__author__ = 'sdelgado'
ACA = "http://127.0.0.1:5001"


def generate_keys():
    # Generate the elliptic curve and the keys
    ec = EC.gen_params(EC.NID_secp256k1)
    ec.gen_key()

    # Generate a Pkey object to store the EC keys
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


def generate_certificate(bc_address, pkey):

    # Get ACA information
    aca_cert_text = b64decode(urllib2.urlopen(ACA + '/get_ca_cert').read())

    aca_cert = X509.load_cert_string(aca_cert_text)

    issuer = aca_cert.get_issuer()

    # Creating a certificate
    cert = X509.X509()

    # Set issuer
    cert.set_issuer(issuer)

    # Generate CS information
    cert_name = X509.X509_Name()
    cert_name.C = 'CT'
    cert_name.ST = 'Barcelona'
    cert_name.L = 'Bellaterra'
    cert_name.O = 'UAB'
    cert_name.OU = 'DEIC'
    cert_name.CN = bc_address
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
    cert.sign(pkey, md='sha256')
    print b64encode(cert.as_pem())


def rpc_test(bc_address):
    rpc_user = "sr_gi"
    rpc_password = "Aqx1xL47eZiKN8v5XjNaJawbmmaMwUKHyTTWEHzrvUbD"

    rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%(rpc_user, rpc_password))

    #print rpc_connection.sendrawtransaction('"01000000011ffe96dfe8107e53e48adbdd23982c4868014bc8e23e70f005be23c19045cde7130000008b483045022100b2e5149d644985237105cd40239cf71e044ce091bc9945ec7c02e1b1f597d80a022071833a074fe4ba4474c88e77410690e16cbf773e63689ad9f36b3c383b231bb40141043806f9d9ee0a383043b0a140fe01c658260bbcbe57535de91eb47b86aa4ec9aced9a0e1d429f2d3d6e47ac267a67d0881498b109690053acd2327e944916ea68ffffffff14e8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88acd81add11000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ac00000000"')

    CS0 = "mpzg9PJ1jNh5NfAU49gcB6zUKJBuMPwEqi"

    #print rpc_connection.getaccount(bc_address)
    print rpc_connection.listtransactions("DCS", 500)
    #print rpc_connection.help()
    #print rpc_connection.listunspent(["mjZJ8ovUXKv6D4GPM91Vq5sGW9AnhSo4dL"], 0, 99)


def split(bc_address):

    private_key_hex = get_priv_key_hex('dcs/private/paysense.key')

    amount = 1000

    while 1:
        print time.strftime("%H:%M:%S")
        print split_bitcoins(bc_address, private_key_hex, amount, 20, 'big', True)
        time.sleep(1800)


def count_splits(bc_address):
    unspent = blockr_unspent(bc_address, 'testnet')
    return count(filter(lambda x: x['value'] == 1000, unspent))


def main():
    bc_address = "mjZJ8ovUXKv6D4GPM91Vq5sGW9AnhSo4dL"
    #rpc_test(bc_address)
    #print count_splits(bc_address)
    #split(bc_address)

    pkey = EVP.load_key("cs/CSs/CS0/private/paysense.key")
    generate_certificate(bc_address, pkey)


if __name__ == '__main__':
    main()
