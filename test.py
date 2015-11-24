from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

from utils.bitcoin.tools import *

__author__ = 'sdelgado'
ACA = "http://127.0.0.1:5001"


def split(btc_address):

    private_key_hex = get_priv_key_hex('dcs/private/paysense.key')

    amount = 1000

    while 1:
        print time.strftime("%H:%M:%S")
        print split_btc(btc_address, private_key_hex, amount, 20, 'small', fee=True)
        time.sleep(1800)


def count_splits(btc_address):
    unspent = blockr_unspent(btc_address, 'testnet')
    return count(filter(lambda x: x['value'] == 1000, unspent))


def main():
    #pass

    rpc_user = "sr_gi"
    rpc_password = "Aqx1xL47eZiKN8v5XjNaJawbmmaMwUKHyTTWEHzrvUbD"
    rpc_connection = AuthServiceProxy("http://"+rpc_user+":"+rpc_password+"@127.0.0.1:18332")
    tx = "0100000004d972c7fd7942bd8b2ed9ba06af9330cae8fcf9945233adddbcd03b3d3a13d107000000008b483045022100a552a9c700281de717be2af15b4a53462993accf06cb8412c0f184116bc5855f022048718bf6998d0f6dec2cff74bf576254093f965b6507b575eaff782da1077afe014104be5c800f6d3eec1227b507099a2c2a5a8a82f2bc71d3670f48ff56de0c33cd8bd0d7575169bc72ebffdaa1dba6617451cf06f9f7ce429ce0da693b99ed0f4bd6ffffffffd972c7fd7942bd8b2ed9ba06af9330cae8fcf9945233adddbcd03b3d3a13d107030000008a47304402204c1c336d6dfd3f939ce7b6c94a6153cb04d9dca6ae65b7e9d881d1dff7b7b847022014be8940fa8e0ed559aae39ed8beb5166c3eef9b6e3eaff484757fcfb570e123014104e20d7847517850116e9c4f0bb3bbba16e3b05b7ba312bed3ee5b12e9c5b51edcb3829f92a4819de00e0c9ccee8fb864ca8215559b6641007fbcab8353b1497a4ffffffffd972c7fd7942bd8b2ed9ba06af9330cae8fcf9945233adddbcd03b3d3a13d107010000008a473044022058955bc65623b14eb62f49f7e61e1b76df7b01b266798f70ee279579232aa31b022035529155556e525876cb69dac9cd89e66307a4eb33afe1e913cc2aa9a2c70ce1014104fba0b10b0c5eecd28555018af20bafa8ea7fc43ba72f64f27df6182bcc7874769404a3eba6818ae6d7246a85795b00e580790ea8f3532f29f053a3eecdd09e0bffffffffd972c7fd7942bd8b2ed9ba06af9330cae8fcf9945233adddbcd03b3d3a13d107020000008b483045022100aed515ced69f1018b579e0317e54829b781eaa3398981e51053ba4108de5e87a02200b97de76ecf1b67b5a6d7b07a953fb33e05ff8bc4ea6cab4d69cd6b018c91a3501410473e1d5409ddd81c74e2cda2878c7efe92a7e36e1e2fd60a1eb559bce96f805dfc7abac3606bc96d9a14b934eee2503d1f35f4857103b0d357491f3cc54fda33dffffffff0428230000000000001976a914ac3b25a72e9192e325fcfe10ce9ac89abf80c57288ac28230000000000001976a914e42f2e8b4afbfe9c958333a45a6d4f564993c9a188ac28230000000000001976a914575b61858c37db7565e781f143238b48c523757f88ac28230000000000001976a91418afde2e174bf923076f868a2a53a3cdb7d905aa88ac00000000"

    try:
        response = rpc_connection.sendrawtransaction(tx)
        print "Transaction broadcast " + response
    except JSONRPCException as e:
        print e.message
        response = None
    print response
if __name__ == '__main__':
    main()
