#!/usr/bin/python

count = 100
host, port = 'localhost', 10000

import sys, os
script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
gnutls_path = os.path.realpath(os.path.join(script_path, '..'))
sys.path[0:0] = [gnutls_path]

from application.debug.timing import timer

from twisted.internet import pollreactor; pollreactor.install()
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor

from gnutls.crypto import *
from gnutls.connection import *
from gnutls.errors import *
from gnutls.interfaces.twisted import X509Credentials

active = count
succesful = 0
failed = 0

class EchoProtocol(LineOnlyReceiver):

    def connectionMade(self):
        self.sendLine('GET /')
        #self.transport.loseConnection()

    def lineReceived(self, line):
        self.transport.loseConnection()

    def connectionLost(self, reason):
        global active, succesful
        succesful += 1
        active -= 1
        if active == 0:
            reactor.stop()

class EchoFactory(ClientFactory):
    protocol = EchoProtocol

    def clientConnectionFailed(self, connector, err):
        global active, failed
        failed += 1
        active -= 1
        if active == 0:
            reactor.stop()

certs_path = os.path.join(script_path, 'certs')

cert = X509Certificate(open(certs_path + '/valid.crt').read())
key = X509PrivateKey(open(certs_path + '/valid.key').read())
ca = X509Certificate(open(certs_path + '/ca.pem').read())
crl = X509CRL(open(certs_path + '/crl.pem').read())
cred = X509Credentials(cert, key, [ca])

echo_factory = EchoFactory()

from optparse import OptionParser
parser = OptionParser(usage="%prog [host]")
parser.add_option("-p", "--port", dest="port", type="int", default=port,
                  help="specify port to connect (default=%s)" % port,
                  metavar="port")

options, args = parser.parse_args()

host, port = args and args[0] or host, options.port

t = timer(count)

for x in range(count):
    reactor.connectTLS(host, port, echo_factory, cred)
reactor.run()

t.end(rate=True, msg="with %s:%d" % (host, port))
if failed > 0:
    print "%d out of %d connections have failed" % (failed, count)

