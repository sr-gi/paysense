import json
import stem.process

from utils.tor.tools import tor_query, SOCKS_PORT
from stem.util import term
from time import sleep

from utils.bitcoin.transactions import get_tx_signature

__author__ = 'sdelgado'

# Start an instance of Tor configured to only exit through Russia. This prints
# Tor's bootstrap information as it starts. Note that this likely will not
# work if you have another Tor instance running.

def print_bootstrap_lines(line):
    if "Bootstrapped " in line:
        print(term.format(line, term.Color.BLUE))


print(term.format("Starting Tor:\n", term.Attr.BOLD))

tor_process = stem.process.launch_tor_with_config(
    config={
        'SocksPort': str(SOCKS_PORT),
    },
    init_msg_handler=print_bootstrap_lines, timeout=60, take_ownership=True,
)

tor_server = "bgpr3ywymhzifnij.onion"

# print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
# print(term.format(tor_query("https://www.atagar.com/echo.php"), term.Color.BLUE))

# SEND OUTPUT

data = [{'value': 47999000, 'address': 'n21HQXRWgbW3XTFTQ44vYDsxi62ve9VXwK'}]
# data = [{'value': 47999000, 'address': 'n4KA9X2S35n3EDLoGmqbzrEgYZTNf3y1Eb'}, {'value': 2000000, 'address': 'mqcKJjxaaUcG37MFA3jvyDkaznWs4kyLyg'}]
data = json.dumps({'outputs': data})
headers = ['Content-type: application/json', 'Accept: text/plain']
time = tor_query(tor_server + "/outputs", 'POST', data, headers)

print "Waiting " + time + " for sending the input"
sleep(float(time))

# SEND INPUTS

data = [{'output': u'cd1eec897705dc3f6df2c9221b55f8bba175b325ced022c201eb5dec71e1c1e1:0', 'value': 50000000}]
# data = [{'output': u'd803b1e18e21ed6d1da82043565e17613070b53a80259b27db139291b4b83092:0', 'value': 50000000}]
data = json.dumps({'inputs': data})
headers = ['Content-type: application/json', 'Accept: text/plain']
time = tor_query(tor_server + "/inputs", 'POST', data, headers)

print "Waiting " + time + " for getting the tx to be signed"
sleep(float(time))

# GET TX FOR SIGNING
tx = tor_query(tor_server + '/signatures')

get_priv_key_hex()

signature = get_tx_signature(tx)

# # SEND SIGNATURE
#
# tx = "0100000002e1c1e171ec5deb01c222d0ce25b375a1bbf8551b22c9f26d3fdc057789ec1ecd0000000000ffffffff9230b8b4919213db279b25803ab5703061175e564320a81d6ded218ee1b103d80000000000ffffffff041868dc02000000001976a914e0be1dbba826125347223d35881031e6a3e2bc5788ac80841e00000000001976a9146eb4e0a11709a52726058e230dfd54899ce7fc0c88ac1868dc02000000001976a914fa0fcbb53dbae5102b5c16760ea46ef9e9276abc88ac80841e00000000001976a9146eb4e0a11709a52726058e230dfd54899ce7fc0c88ac00000000"
#
# # private_key_hex = "a132c58610842880c13958ad7f24dbaecdd555e9c577abd8b7e758c4d972b32b"
# # bitcoin_address = "mpFECAZYV4dXnK2waQC36AoZsAftv5RAkM"
# # public_key_hex = "04334adfad67535594003cd851062de94a90f06f0782b15fa1812796aaae1bfdcdf00820b04e5955a968b0ae46445eff8dc1a3d1e4f864fbd3bce00c31580c7c85"
#
# private_key_hex = "e7ab51292a1c77630d7b016e59dc1b80e2f58a7ee480e8820520aeca1cd31d25"
# bitcoin_address = "mkhrXULTeuwdNGSKVKhR1tjCFMktT6pXFX"
# public_key_hex = "04565226d1ee700878825e3b2ecdd86d1b6980126b463bf2fc541d10289f9c74d4c8e9551859b247deb7ff3c144894b6e9af60f46094c4c86372103f3ad01fb043"
#
# signature, index = get_tx_signature(tx, private_key_hex, bitcoin_address)
# print signature, index
#
# data = {'signature': signature, 'index': index, 'public_key': public_key_hex}
# data = json.dumps({'data': data})
# headers = ['Content-type: application/json', 'Accept: text/plain']
# print(term.format(tor_query(tor_server + "/signatures", 'POST', data, headers), term.Color.BLUE))
#
# # print(term.format(tor_query(tor_server), term.Color.BLUE))
#
# tor_process.kill()  # stops tor
