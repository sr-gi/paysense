import pycurl
import stem.process
from stem.util import term
from StringIO import StringIO

__author__ = 'sdelgado'

SOCKS_PORT = 7000


def tor_query(url, method='GET', data=None, headers=None):
    output = StringIO()

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
        r_code = query.getinfo(pycurl.HTTP_CODE)

        return r_code, output.getvalue()
    except pycurl.error:
        return 500, "Unable to reach " + url


def print_bootstrap_lines(line):
    if "Bootstrapped " in line:
        print(term.format(line, term.Color.BLUE))


def init_tor():
    process = stem.process.launch_tor_with_config(
        config={
            'SocksPort': str(SOCKS_PORT),
        },
        init_msg_handler=print_bootstrap_lines, timeout=60, take_ownership=False)

    return process

