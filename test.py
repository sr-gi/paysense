from bitcointools import *
from bitcoin import *
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import ConfigParser

__author__ = 'sdelgado'


def main():
    bc_address = "mjZJ8ovUXKv6D4GPM91Vq5sGW9AnhSo4dL"

    private_key_hex = get_priv_key_hex('dcs/private/paysense.key')

    amount = 1000

    #print split_bitcoins(bc_address, private_key_hex, amount, 10, 'big')

    rpc_user = "sr_gi"
    rpc_password = "Aqx1xL47eZiKN8v5XjNaJawbmmaMwUKHyTTWEHzrvUbD"

    rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%(rpc_user, rpc_password))

    #print rpc_connection.sendrawtransaction('"01000000011ffe96dfe8107e53e48adbdd23982c4868014bc8e23e70f005be23c19045cde7130000008b483045022100b2e5149d644985237105cd40239cf71e044ce091bc9945ec7c02e1b1f597d80a022071833a074fe4ba4474c88e77410690e16cbf773e63689ad9f36b3c383b231bb40141043806f9d9ee0a383043b0a140fe01c658260bbcbe57535de91eb47b86aa4ec9aced9a0e1d429f2d3d6e47ac267a67d0881498b109690053acd2327e944916ea68ffffffff14e8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88acd81add11000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ac00000000"')
    print rpc_connection.getdifficultyc()


if __name__ == '__main__':
    main()
