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

cred = X509Credentials(cert, key, [ca], [crl])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ssf = ServerSessionFactory(sock, cred)
ssf.bind(('0.0.0.0', 10000))
ssf.listen(100)

while True:
    session, address = ssf.accept()
    try:
        session.handshake()
        peer_cert = session.peer_certificate
        print '\nNew connection!'
        print 'Peer cert:', getattr(peer_cert, 'subject', None)
        print 'Algorithm: ', session.kx_algorithm
        print 'Protocol: ', session.protocol
        print 'Compression: ', session.compression
        print 'Cipher: ', session.cipher
        print 'MAC algorithm: ', session.mac_algorithm
        session.verify_peer()
        cred.check_certificate(peer_cert)
    except Exception, e:
        print 'Handshake failed: ', e
        session.bye()
    else:
        while True:
            try:
                buf = session.recv(1024)
                if buf == 0 or buf == '':
                    print "Peer has closed the session"
                    break
                else:
                    if buf.strip().lower() == 'quit':
                        print "Got quit command, closing connection"
                        session.bye()
                        break
                #buf = buf.rstrip() + " ACK!\r\n"
                session.send(buf)
            except Exception, e:
                print "Error in reception: ", e
                break
    session.shutdown()
    session.close()
