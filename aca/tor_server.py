import threading
import ConfigParser

from stem.control import Controller
from utils.tor.tools import init_tor
from flask import Flask, request, json
from bitcoin import mktx, blockr_pushtx
from time import time
from os import getcwd

from utils.bitcoin.transactions import insert_tx_signature, get_tx_info, check_txs_source, is_spent, local_push

__author__ = "sdelgado"
app = Flask(__name__)

stage = "outputs"
mixing_amount = 10000
server_address = None

stage_time = 60.0 * 5
last_update = 0

outputs = []
inputs = []
signatures = []
unconfirmed = []

tx = None

# Configuration file data loading
config = ConfigParser.ConfigParser()
config.read("paysense.conf")

# ToDo: Check this
cwd = getcwd()
CS_CERTS_PATH = getcwd() + config.get("Paths", "CERTS_PATH", )
a = cwd + CS_CERTS_PATH
DCS_BTC_ADDRESS = config.get("BitcoinAddresses", "DCS", )


@app.route("/", methods=["GET"])
def index():
    return "The current stage is " + stage


@app.route('/get_address', methods=['GET'])
def get_address():
    data = {"address": server_address, "amount": mixing_amount}
    return json.dumps(data)


@app.route("/outputs", methods=["POST", "GET"])
def post_outputs():
    global last_update, outputs
    if stage == "outputs":
        if request.method == "POST" and request.headers["Content-Type"] == "application/json":
            tx_outputs = request.json.get("outputs")
            if len(tx_outputs) > 1:
                message = json.dumps({'data': "Wrong Output. Outputs must have only one source entry.\n"}), 500
            else:
                tx_output = tx_outputs[0]

                if tx_output in outputs:
                    message = json.dumps({'data': "Wrong Output. The chosen output has been already sent.\n"}), 500
                elif tx_output.get("value") != mixing_amount:
                    message = json.dumps({'data': "Wrong Output. The chosen reputation amount doesn't match with the server one.\n"}), 500
                else:
                    outputs.append(tx_output)
                    # Calculate the next update time
                    message = json.dumps({'data': str(abs(stage_time - (time() - last_update)))})
                    print outputs
        else:
            message = json.dumps({'data': "Wrong request\n"}), 500
    else:
        message = json.dumps({'data': "Stage closed\n"}), 500

    return message


@app.route("/inputs", methods=["POST", "GET"])
def post_inputs():
    global last_update, inputs
    if stage == "inputs":
        if request.method == "POST" and request.headers["Content-Type"] == "application/json":
            tx_inputs = request.json.get("inputs")
            if len(tx_inputs) > 1:
                message = json.dumps({'data': "Wrong Input. Inputs must have only one source entry.\n"}), 500
            else:
                tx_input = tx_inputs[0]
                prev_output_hash, prev_output_index = tx_input.get("output").split(":")
                if tx_input in inputs:
                    message = json.dumps({'data': "Wrong input. The chosen input has been already sent.\n"}), 500
                elif is_spent(prev_output_hash, int(prev_output_index)):
                    message = json.dumps({'data': "Wrong input. The chosen had been previously spent.\n"}), 500
                elif not check_input_source(prev_output_hash, prev_output_index):
                    message = json.dumps({'data': "Wrong input. The chosen address contains forbidden payments.\n"}), 500
                else:
                    if get_tx_info(prev_output_hash)['confirmations'] < 6:
                        unconfirmed.append(prev_output_hash)
                    inputs.append(tx_input)
                    # Calculate the next update time
                    message = json.dumps({'data': str(abs(stage_time - (time() - last_update)))})
                    print inputs
        else:
            message = json.dumps({'data': "Wrong request.\n"}), 500
    else:
        message = json.dumps({'data': "Stage closed.\n"}), 500

    return message


@app.route("/signatures", methods=["POST", "GET"])
def get_signatures():
    global tx, signatures
    if stage == "signatures":
        if request.method == "GET" and tx is not None:
            return tx
        elif request.method == "POST" and request.headers["Content-Type"] == "application/json":
            data = request.json.get("data")
            print data
            tx_signature = data["signature"]
            input_index = data["index"]
            public_key_hex = data["public_key"]
            signatures.append([tx_signature, input_index, public_key_hex])
            print signatures

            message = json.dumps({'data': str(abs(stage_time - (time() - last_update)))})
        else:
            message = json.dumps({'data': "Wrong request.\n"}), 500
    else:
        message = json.dumps({'data': "Stage closed.\n"}), 500

    return message


def reset_arrays():
    global outputs, inputs, signatures, unconfirmed

    print "Resetting arrays. Current stage: " + stage
    print "Arrays status: "
    print "outputs : " + str(outputs) + " with len : " + str(len(outputs))
    print "inputs : " + str(inputs) + " with len : " + str(len(inputs))
    print "unconfirmed : " + str(unconfirmed) + " with len : " + str(len(unconfirmed))
    print "signatures : " + str(signatures) + " with len : " + str(len(signatures))

    outputs = []
    inputs = []
    signatures = []
    unconfirmed = []


def insert_signatures(tx):
    for data in signatures:
        signature = data[0]
        index = data[1]
        public_key = data[2]
        tx = insert_tx_signature(tx, index, signature, public_key)

    return tx


def change_stage():
    global stage, tx, inputs, outputs, confirmed, last_update, stage_time

    if stage == "outputs" and len(outputs) > 0:
        stage = "inputs"
    elif stage == "inputs":
        if len(outputs) == len(inputs) and len(outputs) > 0:
            tx = mktx(inputs, outputs)
            print tx
            stage = "signatures"
        else:
            # If a different number of inputs and outputs, on just one of each one, is received, the process is restarted
            reset_arrays()
            stage = "outputs"
    elif stage == "signatures":
        if len(outputs) == len(inputs) == len(signatures):
            tx = insert_signatures(tx)
            print "Final tx: " + tx
            stage = "confirm"
        else:
            # If the three arrays are not of the same size, the process is restarted.
            reset_arrays()
            stage = "outputs"
    elif stage == "confirm":
        confirmed = False

        # Check if there are utxo unconfirmed yet
        if len(unconfirmed) is not 0:
            for utxo in unconfirmed:
                if get_tx_info(utxo)['confirmations'] >= 6:
                    unconfirmed.pop(utxo)

        if len(unconfirmed) is 0:
            confirmed = True

        if confirmed:
            #result = blockr_pushtx(tx, 'testnet')
            result = local_push(tx)
            print result
            print "Transaction correctly published"
            # End of the mixing, starting the process again
            reset_arrays()
            stage = "outputs"
        else:
            # Wait for the inputs to be confirmed
            pass

    last_update = time()
    t = threading.Timer(stage_time, change_stage)
    t.start()
    print " * Current stage: " + stage


def check_input_source(prev_output_hash, prev_output_index):
    info = get_tx_info(prev_output_hash)
    source_address = info.get("to")[int(prev_output_index)]

    if source_address is not None:
        response = check_txs_source(source_address, DCS_BTC_ADDRESS, CS_CERTS_PATH)
    else:
        response = False

    return response


if __name__ == '__main__':

    print(" * Connecting to tor")

    # ToDo: Uncomment, actually running tor from terminal since testing server and client from the same machine
    # tor_process, controller = init_tor()

    # ToDo: Delete the following two lines when the above one is uncommented
    controller = Controller.from_port()
    controller.authenticate()

    # Create a hidden service where visitors of port 80 get redirected to local port 5002

    print(" * Creating ephemeral hidden service")
    response = controller.create_ephemeral_hidden_service({80: 5002}, await_publication=True)
    server_address = response.service_id + ".onion"
    print(" * Our service is available at %s, press ctrl+c to quit" % server_address)

    try:
        last_update = time()
        t = threading.Timer(stage_time, change_stage)
        t.start()

        app.run(port=5002)
    finally:
        print(" * Shutting down our hidden service")
