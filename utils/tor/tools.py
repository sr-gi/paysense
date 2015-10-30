import pycurl
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
        return output.getvalue()
    except pycurl.error as exc:
        return "Unable to reach %s (%s)" % (url, exc)