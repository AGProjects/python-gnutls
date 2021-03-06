#!/usr/bin/python2

import sys, os
script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
gnutls_path = os.path.realpath(os.path.join(script_path, '..'))
sys.path[0:0] = [gnutls_path]

from optparse import OptionParser
from time import time

from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor

import itertools, md5
from OpenSSL import SSL, crypto
from twisted.python import reflect, util
from application import log


# Private - shared between all ServerContextFactories, counts up to
# provide a unique session id for each context
_sessionCounter = itertools.count().next


class _SSLApplicationData(object):
    def __init__(self):
        self.problems = []


# use twisted.internet._sslverify for this context factory, when it becomes available in the debian package -Mircea
class OpenSSLContextFactory(object):
    """A factory for SSL context objects, for server SSL connections."""

    _context = None
    # Older versions of PyOpenSSL didn't provide OP_ALL.  Fudge it here, just in case.
    _OP_ALL = getattr(SSL, 'OP_ALL', 0x0000FFFF)

    method = SSL.TLSv1_METHOD

    def __init__(self, privateKey=None, certificate=None, method=None, verify=False, caCerts=None, 
                 enableSessions=True):
        """
        Create an OpenSSL context SSL connection context factory.

        @param privateKey: A PKey object holding the private key.

        @param certificate: An X509 object holding the certificate.

        @param method: The SSL protocol to use, one of SSLv23_METHOD,
        SSLv2_METHOD, SSLv3_METHOD, TLSv1_METHOD.  Defaults to TLSv1_METHOD.

        @param verify: If True, verify certificates received from the peer and
        fail the handshake if verification fails.  Otherwise, allow anonymous
        sessions and sessions with certificates which fail validation.  By
        default this is False.

        @param caCerts: List of certificate authority certificates to
        send to the client when requesting a certificate.  Only used if verify
        is True, and if verify is True, either this must be specified or
        caCertsFile must be given.  Since verify is False by default,
        this is None by default.

        @param enableSessions: If True, set a session ID on each context.  This
        allows a shortened handshake to be used when a known client reconnects.
        """

        assert (privateKey is None) == (certificate is None), "Specify neither or both of privateKey and certificate"
        self.privateKey = privateKey
        self.certificate = certificate
        if method is not None:
            self.method = method
            
        self.verify = verify
        assert ((verify and caCerts) or
                (not verify)), "Specify client CA certificate information if and only if enabling certificate verification"            
        
        self.caCerts = caCerts
        self.enableSessions = enableSessions

    def getContext(self):
        """Return a SSL.Context object.
        """
        if self._context is None:
            self._context = self._makeContext()
        return self._context

    def _makeContext(self):
        ctx = SSL.Context(self.method)
        ctx.set_app_data(_SSLApplicationData())

        if self.certificate is not None and self.privateKey is not None:
            ctx.use_certificate(self.certificate)
            ctx.use_privatekey(self.privateKey)
            # Sanity check
            ctx.check_privatekey()

        verifyFlags = SSL.VERIFY_NONE
        if self.verify:
            verifyFlags = SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
            if self.caCerts:
                store = ctx.get_cert_store()
                for cert in self.caCerts:
                    store.add_cert(cert)

        def _trackVerificationProblems(conn,cert,errno,depth,preverify_ok):
            return True
        
        ctx.set_verify(verifyFlags, _trackVerificationProblems)
        
        if self.enableSessions:
            sessionName = md5.md5("%s-%d" % (reflect.qual(self.__class__), _sessionCounter())).hexdigest()
            ctx.set_session_id(sessionName)
        
        return ctx


class Certificate(object):
    """Configuration data type. Used to create a OpenSSL.crypto.X509 object from a file given in the configuration file."""
    def __new__(typ, value):
        if isinstance(value, basestring):
            try:
                f = open(value, 'rt')
            except:
                log.warn("Certificate file '%s' could not be open" % value)
                return None
            try:
                try:
                    return crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
                except crypto.Error, e:
                    log.warn("Certificate file '%s' could not be loaded: %s" % (value, str(e)))
                    return None
            finally:
                f.close()
        else:
            raise TypeError, 'value should be a string'


class PrivateKey(object):
    """Configuration data type. Used to create a OpenSSL.crypto.PKey object from a file given in the configuration file."""
    def __new__(typ, value):
        if isinstance(value, basestring):
            try:
                f = open(value, 'rt')
            except:
                log.warn("Private key file '%s' could not be open" % value)
                return None
            try:
                try:
                    return crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
                except crypto.Error, e:
                    log.warn("Private key file '%s' could not be loaded: %s" % (value, str(e)))
                    return None
            finally:
                f.close()
        else:
            raise TypeError, 'value should be a string'


class EchoProtocol(LineOnlyReceiver):

    def connectionMade(self):
        self.sendLine('GET /')
        #self.transport.loseConnection()

    def lineReceived(self, line):
        #print 'received: ', line
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


parser = OptionParser(usage="%prog [host]")
parser.add_option("-c", "--count", dest="count", type="int", default=100,
                  help="how many connections to establish (default = 100)",
                  metavar="N")
parser.add_option("-p", "--port", dest="port", type="int", default=10000,
                  help="specify port to connect (default = 10000)",
                  metavar="port")
parser.add_option("-v", "--verify", dest="verify", action="store_true",
                  default=False, help="verify peer certificates")
parser.add_option("-n", "--no-certs", dest="send_certs", action="store_false",
                  default=True, help="do not send any certificates")

options, args = parser.parse_args()

host, port = args and args[0] or 'localhost', options.port
count = options.count

active = count
succesful = 0
failed = 0

certs_path = os.path.join(gnutls_path, 'examples/certs')

cert = Certificate(certs_path + '/valid.crt')
key = PrivateKey(certs_path + '/valid.key')
ca = Certificate(certs_path + '/ca.pem')
if options.send_certs:
    ctx_factory = OpenSSLContextFactory(key, cert, verify=options.verify, caCerts=[ca])
else:
    ctx_factory = OpenSSLContextFactory(verify=options.verify, caCerts=[ca])

echo_factory = EchoFactory()

start_time = time()

for x in range(count):
    reactor.connectSSL(host, port, echo_factory, ctx_factory)
reactor.run()

duration = time() - start_time
rate = count / duration
print "time={:.2f} sec; rate={} requests/sec with {}:{}".format(duration, int(rate), host, port)

if failed > 0:
    print "{} out of {} connections have failed".format(failed, count)
