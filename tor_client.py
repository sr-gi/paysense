import json
import stem.process
import urllib2

from utils.tor.tools import tor_query, init_tor
from stem.util import term
from time import sleep
from M2Crypto import EC

from utils.bitcoin.tools import get_priv_key_hex, btc_address_from_cert, get_pub_key_hex
from utils.bitcoin.transactions import get_tx_signature

from stem import CircStatus
from stem.control import Controller

__author__ = 'sdelgado'


# Start an instance of Tor configured to only exit through Russia. This prints
# Tor's bootstrap information as it starts. Note that this likely will not
# work if you have another Tor instance running.

def circuit_info(controller):
    for circ in sorted(controller.get_circuits()):
        if circ.status != CircStatus.BUILT:
            continue
    print(" ")
    print("Circuit %s (%s)" % (circ.id, circ.purpose))

    for i, entry in enumerate(circ.path):
        div = '+' if (i == len(circ.path) -1) else '|'
        fingerprint, nickname = entry

        desc = controller.get_network_status(fingerprint, None)
        address = desc.address if desc else 'unknown'

        print (" %s- %s (%s, %s)" % (div, fingerprint, nickname, address))


print "Getting ACA .onion address..."
data = json.loads(urllib2.urlopen("http://158.109.79.170:5001" + '/get_tor_address').read())
tor_server = data.get("address")
amount = data.get("amount")
headers = ['Content-type: application/json', 'Accept: text/plain']

print "Connecting to " + tor_server
# ToDo: Uncomment, actually running tor from terminal since testing server and client from the same machine
# print(term.format("Starting Tor:\n", term.Attr.BOLD))
# tor_process, controller = init_tor()

# ToDo: Delete the following two lines when the above one is uncommented
controller = Controller.from_port()
controller.authenticate()

# SEND OUTPUT

for i in range(2):
    if i is 0:
        data = [{'value': 50000000, 'address': 'n2Y8xrB8grxXWbshsoLrYV2JcCm5iuNA44'}]
    else:
        data = [{'value': 50000000, 'address': 'myMUBDzQJRFZjZtHaq6VeNMEh3QL9RVSJm'}]

    data = json.dumps({'outputs': data})
    code, response = tor_query(tor_server + "/outputs", 'POST', data, headers)

if code is 200:
    print "Output correctly sent. Resetting tor connection"
    controller.new_circuit()

    print "Waiting " + response + " for sending the input"
    sleep(float(response))

    # SEND INPUTS

    for i in range(2):
        if i is 0:
            data = [{'output': u'd8fd9878defa266d0aafb1ec8cdf456d01d664536b0fb65501785759811838a2:1', 'value': 50001000}]
        else:
            data = [{'output': u'2771c07cacb9ab0c637944bb7309e6d3e7fea72934af22af7ec8baf3881ffba9:1', 'value': 50001000}]

        data = json.dumps({'inputs': data})
        code, response = tor_query(tor_server + "/inputs", 'POST', data, headers)

    if code is 200:
        print "Input correctly sent. Resetting tor connection"
        controller.new_circuit()

        print "Waiting " + response + " for getting the tx to be signed"
        sleep(float(response))

        # GET TX FOR SIGNING
        code, tx = tor_query(tor_server + '/signatures')

        for i in range(2):
            private_key_hex = get_priv_key_hex("cs/test/"+str(i)+"/private/paysense.key")
            bitcoin_address = btc_address_from_cert("cs/test/"+str(i)+"/paysense.crt")
            public_key = EC.load_pub_key("cs/test/"+str(i)+"/paysense_public.key")
            public_key_hex = get_pub_key_hex(public_key.pub())

            signature, index = get_tx_signature(tx, private_key_hex, bitcoin_address)

            data = {'signature': signature, 'index': index, 'public_key': public_key_hex}
            data = json.dumps({'data': data})
            code, response = tor_query(tor_server + "/signatures", 'POST', data, headers)

            print code, signature
    else:
        print response
else:
    print response

#tor_process.kill()  # stops tor
