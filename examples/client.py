#!/usr/bin/python2

"""Synchronous client using python-gnutls"""

import sys
import os
import socket

from gnutls.crypto import *
from gnutls.connection import *
from gnutls.errors import GNUTLSError

script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())
cred = X509Credentials(cert, key, [ca], [crl])
context = TLSContext(cred)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
session = ClientSession(sock, context)

try:
    session.connect(('localhost', 10000))
    session.handshake()
    session.verify_peer()
    session.send("test\r\n")
    buf = session.recv(1024)
    print 'Received: ', buf.rstrip()
    session.bye()
    session.close()
except GNUTLSError as e:
    print('Connection failed: {}'.format(e))
    sys.exit(1)
