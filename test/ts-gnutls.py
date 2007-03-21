#!/usr/bin/python

import sys, os
script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
gnutls_path = os.path.realpath(os.path.join(script_path, '..'))
sys.path[0:0] = [gnutls_path]

# This has the side effect of starting logging.
# Do not delete it, even if it is not used anywhere.
from application import log

from optparse import OptionParser

from twisted.internet import pollreactor; pollreactor.install()
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.error import CannotListenError, ConnectionDone
from twisted.internet import reactor

from gnutls.crypto import *
from gnutls.errors import *
from gnutls.interfaces.twisted import X509Credentials

class EchoProtocol(LineOnlyReceiver):

    def connectionMade(self):
        session = self.transport.socket

    def lineReceived(self, line):
        if line == 'quit':
            self.transport.loseConnection()
            return
        self.sendLine(line)

class EchoFactory(Factory):
    protocol = EchoProtocol
    noisy = False

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", default=10000,
                  help="specify port to listen on (default = 10000)",
                  metavar="port")
parser.add_option("-v", "--verify", dest="verify", action="store_true", default=0,
                  help="verify peer certificates (default = no)")

options, args = parser.parse_args()

certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())
cred = X509Credentials(cert, key, [ca], [crl])
cred.verify_peer = options.verify

reactor.listenTLS(options.port, EchoFactory(), cred)
reactor.run()

