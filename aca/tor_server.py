import threading

from stem.control import Controller
from flask import Flask, request, json
from bitcoin import mktx, blockr_pushtx
from time import time

from utils.bitcoin.transactions import insert_tx_signature

__author__ = "sdelgado"

app = Flask(__name__)

stage = "outputs"
server_address = None
stage_time = 45.0
last_update = 0

outputs = []
inputs = []
signatures = []

tx = None

TOR_KEY = "../../aca/private/tor.key"
PASSWORD = "my_password"


@app.route('/get_address', methods=['GET'])
def get_address():
    return server_address


@app.route("/", methods=["GET"])
def index():
    return "The current stage is " + stage


@app.route("/outputs", methods=["POST", "GET"])
def post_outputs():
    global last_update
    if stage == "outputs":
        if request.method == "POST" and request.headers["Content-Type"] == "application/json":
            tx_outputs = request.json.get("outputs")
            if len(tx_outputs) > 1:
                message = json.dumps({'data': "Wrong Output. Outputs must have only one source entry.\n"}), 500
            else:
                outputs.append(tx_outputs[0])
                # Calculate the next update time
                message = str(abs(stage_time - (t - last_update)))
            print outputs
        else:
            message = json.dumps({'data': "Wrong request\n"}), 500
    else:
        message = json.dumps({'data': "Stage closed\n"}), 500

    return message


@app.route("/inputs", methods=["POST", "GET"])
def post_inputs():
    global last_update
    if stage == "inputs":
        if request.method == "POST" and request.headers["Content-Type"] == "application/json":
            tx_inputs = request.json.get("inputs")
            if len(tx_inputs) > 1:
                message = json.dumps({'data': "Wrong Input. Inputs must have only one source entry.\n"}), 500
            else:
                inputs.append(tx_inputs[0])
                # Calculate the next update time
                message = str(abs(stage_time - (time() - last_update)))
                print inputs
        else:
            message = json.dumps({'data': "Wrong request.\n"}), 500
    else:
        message = json.dumps({'data': "Stage closed.\n"}), 500

    return message


@app.route("/signatures", methods=["POST", "GET"])
def get_signatures():
    global tx
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

            return "OK"
        else:
            return "Wrong request"
    else:
        return "Stage closed"


def reset_arrays():
    global outputs, inputs, signatures

    print "Resetting arrays. Current stage :" + stage
    print "Arrays status: "
    print "outputs : " + str(outputs) + " with len : " + str(len(outputs))
    print "inputs : " + str(inputs) + " with len : " + str(len(inputs))
    print "signatures : " + str(signatures) + " with len : " + str(len(signatures))

    outputs = []
    inputs = []
    signatures = []


def insert_signatures(tx):
    for data in signatures:
        signature = data[0]
        index = data[1]
        public_key = data[2]
        tx = insert_tx_signature(tx, index, signature, public_key)

    return tx


def change_stage():
    global stage, tx, inputs, outputs, last_update

    if stage == "outputs" and len(outputs) > 0:
        stage = "inputs"
    elif stage == "inputs":
        if len(outputs) == len(inputs):
            tx = mktx(inputs, outputs)
            print tx
            stage = "signatures"
        else:
            # If a different number of groups of inputs that group of outputs is received, the process is restarted
            reset_arrays()
            stage = "outputs"
    elif stage == "signatures":
        if len(outputs) == len(inputs) == len(signatures):
            tx = insert_signatures(tx)
            print "Final tx: " + tx
            result = blockr_pushtx(tx, 'testnet')
            print result
        # End of the mixing, starting the process again
        reset_arrays()
        stage = "outputs"

    last_update = time()
    t = threading.Timer(stage_time, change_stage)
    t.start()
    print " * Current stage: " + stage


if __name__ == '__main__':

    print(" * Connecting to tor")

    with Controller.from_port() as controller:
        controller.authenticate(PASSWORD)

        # Create a hidden service where visitors of port 80 get redirected to local
        # port 5002

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
