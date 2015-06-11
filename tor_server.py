__author__ = 'sdelgado'

from stem.control import Controller
from flask import Flask, request

app = Flask(__name__)

outputs = []
inputs = []
signatures = []

@app.route('/outputs', methods=['POST'])
def post_outputs():
    if request.headers['Content-Type'] == 'application/json':
        message = str(request.json.get("outputs"))
        print message
        return "Outputs room"


@app.route('/inputs', methods=['POST'])
def post_inputs():
    if request.headers['Content-Type'] == 'application/json':
        message = str(request.json.get("outputs"))
        print message
        return "Inputs room"


@app.route('/signatures', methods=['GET'])
def get_signatures():
    if request.headers['Content-Type'] == 'application/json':
        message = str(request.json.get("outputs"))
        print message
        return "Signatures room"

print(' * Connecting to tor')

with Controller.from_port() as controller:
    controller.authenticate("my_password")

    # Create a hidden service where visitors of port 80 get redirected to local
    # port 5002

    print(" * Creating ephemeral hidden service")
    response = controller.create_ephemeral_hidden_service({80: 5002}, await_publication=True)
    print(" * Our service is available at %s.onion, press ctrl+c to quit" % response.service_id)

    try:
        app.run(port=5002)
    finally:
        print(" * Shutting down our hidden service")
