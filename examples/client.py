#!/usr/bin/python

import sys, os
script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
gnutls_path = os.path.realpath(os.path.join(script_path, '..'))
sys.path[0:0] = [gnutls_path]

import socket
from gnutls.crypto import *
from gnutls.connection import *

certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())

ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())

cred = X509Credentials(cert, key)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

session = ClientSession(sock, cred)

session.connect(('localhost', 10000))
session.handshake()
session.send("test\r\n")
buf = session.recv(1024)
print 'Received: ', buf.rstrip()
session.bye()
session.shutdown()
session.close()

