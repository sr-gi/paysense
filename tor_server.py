__author__ = "sdelgado"

import threading

from stem.control import Controller
from flask import Flask, request, json
from bitcoin import mktx
from bitcointransactions import insert_signature

app = Flask(__name__)

stage = "outputs"
stage_time = 30.0

outputs = []
inputs = []
signatures = []

n_outputs = 0
tx = None

# ToDo: Delete this route, just for testing
@app.route("/change_stage", methods=["GET"])
def change_state():
    global stage
    new_stage = request.args.get("stage")

    if new_stage in {"outputs", "inputs", "signatures"}:
        stage = new_stage
        message = "Stage changed to " + new_stage
    else:
        message = "Wrong stage"
    return message


@app.route("/", methods=["GET"])
def index():
    return "The current stage is " + stage


@app.route("/outputs", methods=["POST", "GET"])
def post_outputs():
    global n_outputs
    if stage == "outputs":
        if request.method == "GET":
            message = "Stage open"
        elif request.method == "POST" and request.headers["Content-Type"] == "application/json":
            tx_outputs = request.json.get("outputs")
            for tx_output in tx_outputs:
                outputs.append(tx_output)

            message = "OK"
            n_outputs += 1
            print outputs
        else:
            message = "Wrong request"
    else:
        message = "Stage closed"

    return message


@app.route("/inputs", methods=["POST", "GET"])
def post_inputs():
    if stage == "inputs":
        if request.method == "GET":
            message = "Stage open"
        elif request.method == "POST" and request.headers["Content-Type"] == "application/json":
            tx_inputs = request.json.get("inputs")
            if len(tx_inputs) > 1:
                message = "Wrong Input. Inputs must have only one source entry"
            else:
                inputs.append(tx_inputs[0])
                message = "OK"
                print inputs
        else:
            message = "Wrong request"
    else:
        message = "Stage closed"

    return message


@app.route("/signatures", methods=["POST", "GET"])
def get_signatures():
    global tx
    if stage == "signatures":
        if request.method == "GET" and tx is not None:
            return tx
        elif request.method == "POST" and request.headers["Content-Type"] == "application/json":
            data = request.json.get("data")
            tx_signature = data["signature"]
            input_index = data["index"]
            signatures.append([tx_signature, input_index])
            print signatures

            return "OK"
        else:
            return "Wrong request"
    else:
        return "Stage closed"


def reset_arrays():
    global outputs, inputs, signatures, n_outputs

    print "Reseting arrays. Current stage :" + stage
    print "Arrays status: "
    print "outputs :" + str(outputs) + "with len (n_outputs) :" +str(n_outputs)
    print "inputs :" + str(inputs) + "with len :" +str(len(inputs))
    print "outputs :" + str(signatures) + "with len :" +str(len(signatures))

    outputs = inputs = signatures = []
    n_outputs = 0

def insert_signatures(tx):
    for data in signatures:
        signature = data[0]
        index = data[1]
        public_key = data[2]
        tx = insert_signature(tx, index, signature, public_key)

    return tx


def change_stage():
    global stage, tx, n_outputs, inputs, outputs

    if stage == "outputs" and n_outputs > 0:
        stage = "inputs"
    elif stage == "inputs":
        if n_outputs == len(inputs) and n_outputs != 0:
            tx = mktx(inputs, outputs)
            print tx
            stage = "signatures"
        else:
            # If a different number of groups of inputs that group of outputs is received, the process is restarted
            reset_arrays()
            stage = "outputs"
    elif stage == "signatures":
        if n_outputs == len(inputs) == len(signatures) and n_outputs != 0:
            insert_signatures(tx)
            print "Final tx: " + tx
        # End of the mixing, starting the process again
        reset_arrays()
        stage = "outputs"

    t = threading.Timer(stage_time, change_stage)
    t.start()
    print " * Current stage: " + stage


if __name__ == '__main__':

    print(" * Connecting to tor")

    with Controller.from_port() as controller:
        controller.authenticate("my_password")

        # Create a hidden service where visitors of port 80 get redirected to local
        # port 5002

        print(" * Creating ephemeral hidden service")
        response = controller.create_ephemeral_hidden_service({80: 5002}, await_publication=True)
        print(" * Our service is available at %s.onion, press ctrl+c to quit" % response.service_id)

        # ToDo: Remove this part, is just for testing
        # Save .onion address in a file to be used by the client
        f = open("onion_server.txt", 'w')
        f.write(response.service_id)
        f.close()
        #########################################################

        try:
            t = threading.Timer(stage_time, change_stage)
            t.start()

            app.run(port=5002)
        finally:
            print(" * Shutting down our hidden service")
