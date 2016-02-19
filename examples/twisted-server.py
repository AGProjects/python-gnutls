#!/usr/bin/env python

"""Asynchronous server using Twisted with GNUTLS"""

import sys
import os

from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.error import CannotListenError, ConnectionDone
from twisted.internet import reactor

from gnutls.constants import *
from gnutls.crypto import *
from gnutls.errors import *
from gnutls.interfaces.twisted import TLSContext, X509Credentials

class EchoProtocol(LineOnlyReceiver):

    def connectionMade(self):
        session = self.transport.socket
        try:
            peer_name = session.peer_certificate.subject
        except AttributeError:
            peer_name = 'Unknown'
        print '\nNew connection from: %s' % peer_name
        print 'Protocol:      %s' % session.protocol
        print 'KX algorithm:  %s' % session.kx_algorithm
        print 'Cipher:        %s' % session.cipher
        print 'MAC algorithm: %s' % session.mac_algorithm
        print 'Compression:   %s' % session.compression

    def lineReceived(self, line):
        if line == 'quit':
            self.transport.loseConnection()
            return
        self.sendLine(line)

    def connectionLost(self, reason):
        if reason.type != ConnectionDone:
            print "Connection was lost: %s" % reason.value

class EchoFactory(Factory):
    protocol = EchoProtocol

script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())
cred = X509Credentials(cert, key, [ca], [crl])
cred.verify_peer = True
context = TLSContext(cred, session_parameters="NORMAL:+COMP-DEFLATE")

reactor.listenTLS(10000, EchoFactory(), context)
reactor.run()

