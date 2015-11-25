# Copyright (c) <2015> <Sergi Delgado Segura>
# Distributed under the BSD software license, see the accompanying file LICENSE

import pycurl
import stem.process

from stem.control import Controller
from stem.util import term
from StringIO import StringIO

__author__ = 'sdelgado'

SOCKS_PORT = 9050
CONTROL_PORT = 9051


def tor_query(url, method='GET', data=None, headers=None, socks_port=None):
    """ Performs a http query using tor.

    :param url: server address.
    :type url: str
    :param method: request method (GET, POST, ...).
    :type method: str
    :param data: data to be sent to the server.
    :param data: JSON dumped object
    :param headers: headers of the request.
    :type headers: str array
    :param socks_port: local socket port where tor is listening to requests (configurable in tor.rc).
    :type socks_port: int
    :return: response code and some server response data.
    :rtype: str, str
    """
    output = StringIO()

    if socks_port is None:
        socks_port = SOCKS_PORT

    query = pycurl.Curl()
    query.setopt(pycurl.URL, url)
    query.setopt(pycurl.PROXY, 'localhost')
    query.setopt(pycurl.PROXYPORT, socks_port)
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
        r_code = query.getinfo(pycurl.HTTP_CODE)

        return r_code, output.getvalue()
    except pycurl.error:
        return 500, "Unable to reach " + url


def print_bootstrap_lines(line):
    """ Print the bootstrap lines.

    :param line: line to be printed.
    :type line: str
    :return: None.
    """
    if "Bootstrapped " in line:
        print(term.format(line, term.Color.BLUE))


def init_tor(socks_port=None, control_port=None):
    """ Initiates a tor connection.

    :param socks_port: local port socket where tor will listen to requests (configurable in tor.rc).
    :type socks_port: int
    :param control_port: local port where tor will listen to control requests (configurable in tor.rc).
    :type control_port: int
    :return: a tor process and a controller of the process.
    :rtype: process, controller
    """
    if socks_port is None:
        socks_port = SOCKS_PORT
    if control_port is None:
        control_port = CONTROL_PORT

    process = stem.process.launch_tor_with_config(
        config={
            'SocksPort': str(socks_port),
            'ControlPort': str(control_port)
        },
        init_msg_handler=print_bootstrap_lines, timeout=60, take_ownership=True)

    controller = Controller.from_port()
    controller.authenticate()

    return process, controller

