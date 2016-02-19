#!/usr/bin/env python

"""Asynchronous client using Twisted with GNUTLS"""

import sys
import os

from twisted.internet.error import ConnectionDone
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor

from gnutls.constants import *
from gnutls.crypto import *
from gnutls.errors import *
from gnutls.interfaces.twisted import TLSContext, X509Credentials

class EchoProtocol(LineOnlyReceiver):

    def connectionMade(self):
        self.sendLine('echo')

    def lineReceived(self, line):
        print 'received: %s' % line
        self.transport.loseConnection()

    def connectionLost(self, reason):
        if reason.type != ConnectionDone:
            print "connection was lost: %s" % reason.value
        reactor.stop()

class EchoFactory(ClientFactory):
    protocol = EchoProtocol

    def clientConnectionFailed(self, connector, err):
        print "connection failed: %s" % err.value
        reactor.stop()


script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())
cred = X509Credentials(cert, key, [ca])
cred.verify_peer = True
context = TLSContext(cred, session_parameters="NORMAL:-COMP-ALL:+COMP-DEFLATE:+COMP-NULL")

reactor.connectTLS('localhost', 10000, EchoFactory(), context)
reactor.run()

