__author__ = 'sdelgado'

from flask import Flask, url_for
from flask import request
app = Flask(__name__)

@app.route('/', methods=['POST'])
def api_echo():

    if request.method == 'POST':
        return "ECHO: POST\n"

if __name__ == '__main__':
    app.run()