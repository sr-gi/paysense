from bitcoin import *
from bitcoinrpc.authproxy import AuthServiceProxy
from utils.bitcoin.transactions import get_tx_info

from utils.bitcoin.tools import *

__author__ = 'sdelgado'
ACA = "http://127.0.0.1:5001"


def rpc_test(tx_hex):
    rpc_user = "sr_gi"
    rpc_password = "Aqx1xL47eZiKN8v5XjNaJawbmmaMwUKHyTTWEHzrvUbD"

    rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%(rpc_user, rpc_password))

    #print rpc_connection.sendrawtransaction('"01000000011ffe96dfe8107e53e48adbdd23982c4868014bc8e23e70f005be23c19045cde7130000008b483045022100b2e5149d644985237105cd40239cf71e044ce091bc9945ec7c02e1b1f597d80a022071833a074fe4ba4474c88e77410690e16cbf773e63689ad9f36b3c383b231bb40141043806f9d9ee0a383043b0a140fe01c658260bbcbe57535de91eb47b86aa4ec9aced9a0e1d429f2d3d6e47ac267a67d0881498b109690053acd2327e944916ea68ffffffff14e8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ace8030000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88acd81add11000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ac00000000"')

    CS0 = "mpzg9PJ1jNh5NfAU49gcB6zUKJBuMPwEqi"

    #print rpc_connection.getaccount(btc_address)
    #print rpc_connection.listtransactions("DCS", 500)
    #print rpc_connection.help()
    #raw = rpc_connection.decoderawtransacton(tx_hex)
    response = rpc_connection.sendrawtransaction(tx_hex)

    print response
    #print rpc_connection.sendrawtransaction("0100000006040f77b4a53a7830eecc0151bc25163dcc8f2ec649022b8d821065ce17a0a6e5000000008b483045022100a2dddce58698afc4e97b576253da5cf02df1a941fd80bf644c65115eff7d4a300220741cd096b2981149e5e874f1a97078a673fff830a9f1928e31f9ed5a9a9e575901410455f2ff53b2f9b50aeab24881c336dea216662e755801d61b9a0bc19e304f8d033e908b63c1e7eef6073f016661e2abac9e1e7943a08120fc12e72e6ddb0535a5ffffffffb5a3821ca44b2ce592f3a9cb7464e8797acf1909ccd00bb7708b3b2062045e12000000008a473044022051f8d82f5d5714d486a4eb31c6fc511b7f9b1bfe436b82eff3877c660783841d02202b3881669127caadb3568f2b0b487fb0067b185958520d5d43b5a386a670129101410455f2ff53b2f9b50aeab24881c336dea216662e755801d61b9a0bc19e304f8d033e908b63c1e7eef6073f016661e2abac9e1e7943a08120fc12e72e6ddb0535a5ffffffff416c21f7e7ffd91429458b065db87f91ca0cdad88ff1dbe2a5514aa353fe9d36000000008b483045022100a30c6ad1eff5ea8254ef5fc4c0e506786dd48543986bad2d71897a12f8fd7785022019825cbc9c44af88cca550abdecab7edad8599c946168ece300f8890b8ba47fb01410455f2ff53b2f9b50aeab24881c336dea216662e755801d61b9a0bc19e304f8d033e908b63c1e7eef6073f016661e2abac9e1e7943a08120fc12e72e6ddb0535a5ffffffff124559ed83a4f6f945e9b3ecdc2983543b1c489aa0faffeefd71d4304fc711ab000000008b483045022100b2931d2f590e3b9509ad73c129c49460132fb74c6c083baffdca48da40354f3402205b21934c83a980bafd4061a8989adfd35a10c64bbf64cd4c4f308d46566ed45401410455f2ff53b2f9b50aeab24881c336dea216662e755801d61b9a0bc19e304f8d033e908b63c1e7eef6073f016661e2abac9e1e7943a08120fc12e72e6ddb0535a5ffffffff962a1838b96da99d5596e523a4e2c92c8a7a1ac6cf2f065dbc375fb01a6164600000000089463043021f227d5b127a8ef39bae02251ec2bb69fc28728fa0f2e879f9c16e6a437a451302200c7853b0ee6ba7c0407786d32a34f26ff458af253fb81aba1578e4fa41c71a5301410455f2ff53b2f9b50aeab24881c336dea216662e755801d61b9a0bc19e304f8d033e908b63c1e7eef6073f016661e2abac9e1e7943a08120fc12e72e6ddb0535a5ffffffff13cb9ba4197e74a7cd49d279dbf21b08cbf0f7e4dd35d3e2dd891ad1a8db638e000000008a47304402200b91ecfa13b84442ea23ce631d35d5479ef4e0204107194a50c80cecb41991e9022054addba8b869dce9f22e35f17ff269f3eab9bd9c81eec9b97c50337b175d627401410455f2ff53b2f9b50aeab24881c336dea216662e755801d61b9a0bc19e304f8d033e908b63c1e7eef6073f016661e2abac9e1e7943a08120fc12e72e6ddb0535a5ffffffff0188130000000000001976a9142c51e5ad0d9825c65c86116f9ba41e492381d92e88ac00000000")
    #print rpc_connection.listunspent(["mjZJ8ovUXKv6D4GPM91Vq5sGW9AnhSo4dL"], 0, 99)


def split(btc_address):

    private_key_hex = get_priv_key_hex('dcs/private/paysense.key')

    amount = 1000

    while 1:
        print time.strftime("%H:%M:%S")
        print split_btc(btc_address, private_key_hex, amount, 20, 'big', fee=True)
        time.sleep(1800)


def count_splits(btc_address):
    unspent = blockr_unspent(btc_address, 'testnet')
    return count(filter(lambda x: x['value'] == 1000, unspent))


def main():
    #pass
    #rpc_test("")
    #print get_balance("mjVj8DTsi7nEMH2oarr63ZKdqhA8eZoQZe", 'testnet')

    # from utils.bitcoin.transactions import get_tx_info, history_testnet
    #
    #
    # print get_tx_info("3e2bb1d76e77c3f4bdeac777616bf2963f95c4351c387f57aa967c6e8abd22b7")

    #split("mjZJ8ovUXKv6D4GPM91Vq5sGW9AnhSo4dL")

    from utils.bitcoin.transactions import local_push

    print local_push("0100000004d08d026c9c039507daa57d07f20113b8adf0f58726efa8667c833732c2831bed000000008a473044022037c0dceb978784d1c47ffa97687b4b9ee9577ab4f855cde5af4082ef349f142002204edb78af61878dd74f5ce1deb398423dc761d9302c938b7949baf5bf3bcd8d6701410477f992ca89cf3394ae687cf539a6cae369ee86ae6aa3e96b2e640578a53e68d711f662f506aae45302503df067ee3fb226d0374aed481586b2b4c45f4631d14cffffffff4381d03cc2583a324160ef9f51c88d36783982bf3010a890c5703562cce81797000000008b4830450221008e9f257de11ff22ce6c8c3677fce2483b5f0cb725edc123c48711aa95c3795b902207a943d304a9118caaf982c47c6637c1cc81471c6f5c7e211ac4996210e96270f0141048a9d17b8f31e8ea95c883ca550018679d6406aedff1da74914a9c6c375c0bf8dffefdbd6a05c0192b2eb04cfb1e35f77d0a39ddcec91436466f8fac39d8e2fe7ffffffff49cb87243d2915630b67a8a0f7691545396617575d206a49ea52be9a10ecab14000000008a473044022074129dd3e2401b8877ca32081f54e19689016018668bd0cac74e6e05d94e13b5022061f09c4e7db3bdb96613b9fe31c3c386006b3b4997c30cee705e126a31d9cb9201410414f53c23ad239aa65140c966610b35d187dc2d607a5e26450580e715ebc835123bcfae95388bddbb03b3272bf4211a5f6e63f8eb14d3cbd0920af1808b59e36afffffffff9fff3b5999bdef5a1172a20507252f28d83267c19127bcd7d48323e71295d8c000000008b483045022100eb382568d203a9ef3280a2dc71db6ea4671d257929256cbcbfba60a0b477a62c02207bfa7a29c1b071fc45941eb0e93596326f829c2167bec9a9e522df800051fcec014104ffc4badc9a48baad59a6c358aff145eae6d55a697e95488df10826af8fc14c2c8709916ecaef2c3785d0573aef0efc1103097c65a98b1d9689cc2beb86a3822fffffffff0410270000000000001976a914e94c3443ab70a48c94bba276c574231d48d163fa88ac10270000000000001976a914a67a4185a47ed35531f29563ae6a6c911aa3a76888ac10270000000000001976a914300439ba78639286209f6aa6322daf20d8581d7388ac10270000000000001976a914adec383df803408e52015b10909503b62ae105bc88ac00000000")


if __name__ == '__main__':
    main()
