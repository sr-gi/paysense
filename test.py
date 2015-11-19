from utils.bitcoin.tools import *

__author__ = 'sdelgado'
ACA = "http://127.0.0.1:5001"


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
    pass

if __name__ == '__main__':
    main()
