__author__ = 'sdelgado'

import pycurl
import json
import StringIO
import stem.process

from stem.util import term
from bitcointransactions import get_tx_signature

SOCKS_PORT = 7000

# ToDo: Remove this part, is just for testing
# Get the .onion address from the file
f = open("onion_server.txt", 'r')
tor_server = f.read() + ".onion"
##############################################

def query(url, method='GET', data=None, headers=None):

    output = StringIO.StringIO()

    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, SOCKS_PORT)
    query.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)
    query.setopt(pycurl.WRITEFUNCTION, output.write)

    if method == 'POST':
        if data is None or headers is None:
            return "Not enough parameters for POST"
        else:
            query.setopt(pycurl.HTTPHEADER, headers)
            query.setopt(pycurl.POST, 1)
            query.setopt(pycurl.POSTFIELDS, data)

    try:
        query.perform()
        return output.getvalue()
    except pycurl.error as exc:
        return "Unable to reach %s (%s)" % (url, exc)


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

#print(term.format("\nChecking our endpoint:\n", term.Attr.BOLD))
#print(term.format(query("https://www.atagar.com/echo.php"), term.Color.BLUE))

# SEND OUTPUTS

data = [{'value': 120743010, 'address': 'mkhrXULTeuwdNGSKVKhR1tjCFMktT6pXFX'}, {'value': 3734350, 'address': 'mpFECAZYV4dXnK2waQC36AoZsAftv5RAkM'}]
data = json.dumps({'outputs': data})
headers = ['Content-type: application/json', 'Accept: text/plain']
#print(term.format(query(tor_server + "/outputs", 'POST', data, headers), term.Color.BLUE))

# SEND INPUTS

data = [{'output': u'4d65acc9ea8c6dcd41aba7d04d70aae03d2ab40abe7425c8c94cefc766aa5fa0:0', 'value': 124478360}]
data = json.dumps({'inputs': data})
headers = ['Content-type: application/json', 'Accept: text/plain']
#print(term.format(query(tor_server + "/inputs", 'POST', data, headers), term.Color.BLUE))

# GET TX FOR SIGNING
#print(term.format(query(tor_server + '/signatures'), term.Color.BLUE))

# SEND SIGNATURE

tx = "0100000001a05faa66c7ef4cc9c82574be0ab42a3de0aa704dd0a7ab41cd6d8ceac9ac654d0000000000ffffffff0262643207000000001976a91438e8639a08fc099fcff648dca27f01c2d32dcac788ac4efb3800000000001976a9145fbfbf7fe54155a94c457f627507ee186c1e053c88ac00000000"
private_key_hex = "e7ab51292a1c77630d7b016e59dc1b80e2f58a7ee480e8820520aeca1cd31d25"
bitcoin_address = "n4KA9X2S35n3EDLoGmqbzrEgYZTNf3y1Eb"
signature, index = get_tx_signature(tx, private_key_hex, bitcoin_address)

#ToDo: The PK musst be sent with the signature and the index
data = {'signature': signature, 'index': index}
data = json.dumps({'data': data})
headers = ['Content-type: application/json', 'Accept: text/plain']
print(term.format(query(tor_server + "/signatures", 'POST', data, headers), term.Color.BLUE))

#print(term.format(query(tor_server), term.Color.BLUE))

tor_process.kill()  # stops tor
