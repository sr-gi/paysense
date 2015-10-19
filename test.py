from bitcointools import *
from bitcoin import *
from bitcoinrpc.authproxy import AuthServiceProxy

__author__ = 'sdelgado'
ACA = "http://127.0.0.1:5001"


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


def rsa_test():

    from Crypto.PublicKey import RSA
    from random import randint

    f = open("aca/private/paysense.key", "r")
    sk_string = f.read()
    f.close()
    cert = X509.load_cert("aca/paysense.crt")

    sk = RSA.importKey(sk_string)
    pk = RSA.importKey(cert.get_pubkey().as_der())

    m = long(3)
    r = long(randint(1, 1000))

    b_m = pk.blind(m, r)
    signed_b_m = sk.sign(b_m, 1)[0]
    md = sk.sign(m, 1)[0]

    assert pk.unblind(signed_b_m, r) == md



    #########################################
    ################# TEST ##################
    #########################################

    # from Crypto.Util.number import bytes_to_long
    # from Crypto.Signature import PKCS1_v1_5
    # import SHA256
    #
    # assert pk.verify(cert_hash, [signature, 0])
    #
    # ca_pkey = EVP.load_key("../aca/private/paysense.key")
    #
    # sig_scheme = PKCS1_v1_5.new(sk)
    # hash = SHA256.new(blinded_hash)
    #
    # signature_PKCS1_1 = sig_scheme.sign(hash)
    # signature_PKCS1_2 = ca_pkey.get_rsa().sign(cert_hash, "sha256")
    #
    # assert signature_PKCS1_1 == signature_PKCS1_2
    #
    # print "TextBook signature: \t" + str(signature)
    #
    # print "PKCS1 signature: \t\t" + str(bytes_to_long(signature_PKCS1_2))


    #########################################
    #########################################

def main():
    bc_address = "mjZJ8ovUXKv6D4GPM91Vq5sGW9AnhSo4dL"
    #rpc_test(bc_address)
    #print count_splits(bc_address)
    #split(bc_address)
    rsa_test()



if __name__ == '__main__':
    main()
