# Copyright (C) 2007 AG Projects
#

"""GNUTLS Twisted interface"""

__all__ = ['connectTLS', 'listenTLS']

import new
import socket
import time
try:
    import fcntl
except ImportError:
    fcntl = None

from errno import EWOULDBLOCK

from twisted.internet import base, address, tcp
from twisted.internet import error
from twisted.internet.protocol import BaseProtocol

from gnutls.connection import *
from gnutls.errors import *

class AsyncClientSession(ClientSession):

    def recv(self, bufsize):
        try:
            return super(AsyncClientSession, self).recv(bufsize)
        except WouldBlockError, e:
            raise socket.error(EWOULDBLOCK)
        except GNUTLSError:
            return ''

    def send(self, buffer):
        try:
            buffer = str(buffer)
            return super(AsyncClientSession, self).send(buffer)
        except WouldBlockError, e:
            raise socket.error(EWOULDBLOCK)
        except GNUTLSError:
            return -1


class AsyncServerSession(ServerSession):

    def recv(self, bufsize):
        try:
            return super(AsyncServerSession, self).recv(bufsize)
        except WouldBlockError, e:
            raise socket.error(EWOULDBLOCK)
        except GNUTLSError:
            return ''

    def send(self, buffer):
        try:
            buffer = str(buffer)
            return super(AsyncServerSession, self).send(buffer)
        except WouldBlockError, e:
            raise socket.error(EWOULDBLOCK)
        except GNUTLSError:
            return -1


class TLSClient(tcp.Client):
    """I am an TLS client."""
    
    def __init__(self, host, port, bindAddress, credentials, connector, reactor=None):
        self.credentials = credentials
        tcp.Client.__init__(self, host, port, bindAddress, connector, reactor)

    def getHost(self):
        """Returns the address from which I am connecting."""
        h, p = self.socket.getsockname()
        return address.IPv4Address('TCP', h, p, 'TLS')

    def getPeer(self):
        """Returns the address that I am connected."""
        return address.IPv4Address('TCP', self.addr[0], self.addr[1], 'TLS')

    def getPeerCertificate(self):
        return self.socket.peer_certificate

    def createInternetSocket(self): # overrides BaseClient.createInternetSocket
        """(internal) Create a non-blocking socket using
        self.addressFamily, self.socketType.
        """
        s = socket.socket(self.addressFamily, self.socketType)
        s.setblocking(0)
        if fcntl and hasattr(fcntl, 'FD_CLOEXEC'):
            old = fcntl.fcntl(s.fileno(), fcntl.F_GETFD)
            fcntl.fcntl(s.fileno(), fcntl.F_SETFD, old | fcntl.FD_CLOEXEC)
        sess = AsyncClientSession(s, self.credentials)
        return sess

    def doHandshake(self):
        try:
            self.socket.handshake()
        except WouldBlockError, e:
            self.startReading()
            return
        except GNUTLSError, e:
            self.failIfNotConnected(err = error.getConnectError(str(e)))
            return
        
        # verify peer after the handshake was completed
        try:
            self.socket.verify_peer()
        except CertificateError, e:
            self.failIfNotConnected(err = error.getConnectError(str(e)))
            return

        # If I have reached this point without raising or returning, that means
        # that the handshake has finished succesfully.
        del self.doRead
        # we first stop and then start, to reset any references to the old doRead
        self.stopReading()
        tcp.Client._connectDone(self)
        
    def startTLS(self):
        self.doRead = self.doHandshake
        self.doHandshake()

    def _connectDone(self):
        self.startReading()
        self.startTLS()

class TLSConnector(base.BaseConnector):
    def __init__(self, host, port, factory, credentials, timeout, bindAddress, reactor=None):
        self.host = host
        self.port = port
        self.bindAddress = bindAddress
        self.credentials = credentials
        base.BaseConnector.__init__(self, factory, timeout, reactor)

    def _makeTransport(self):
        return TLSClient(self.host, self.port, self.bindAddress, self.credentials, self, self.reactor)

    def getDestination(self):
        return address.IPv4Address('TCP', self.host, self.port, 'TLS')


class TLSServer(tcp.Server):
    """I am an TLS server.
    
    I am a serverside network connection transport; a socket which came from an
    accept() on a server.
    """

    def getHost(self):
        """Return server's address."""
        h, p = self.socket.getsockname()
        return address.IPv4Address('TCP', h, p, 'TLS')

    def getPeer(self):
        """Return address of peer."""
        h, p = self.client
        return address.IPv4Address('TCP', h, p, 'TLS')

    def getPeerCertificate(self):
        return self.socket.peer_certificate

    def doHandshake(self):
        try:
            self.socket.handshake()
        except WouldBlockError, e:
            self.startReading()
            return
        except GNUTLSError, e:
            self.connectionLost(reason = str(e))
            return
        
        # verify peer after the handshake was completed
        try:
            self.socket.verify_peer()
        except CertificateError, e:
            self.stopReading()
            self.connectionLost(reason = str(e))
            return
        
        # If I have reached this point without raising or returning, that means
        # that the handshake has finished succesfully.
        del self.doRead
        # we first stop and then start, to reset any references to the old doRead
        self.stopReading()
        self.startReading()
        self.protocol.makeConnection = self._originalMakeConnection
        self.protocol.makeConnection(self)

    def doBye(self):
        try:
            self.socket.bye()
        except WouldBlockError, e:
            self.startReading()
            return
        except:
            pass
        del self.doRead
        self.stopReading()
        self.startReading()
        tcp.Server.connectionLost(self, self._connectionLostReason)
        
    def connectionLost(self, reason):
        # if str(reason.value) == 'Uh: Filedescriptor went away.': return
        self._connectionLostReason = reason
        self.startReading()
        self.doRead = self.doBye
        self.doBye() # we need to initiate the TLS bye procedure

    def startTLS(self):
        self.startReading()
        self.doRead = self.doHandshake


class TLSPort(tcp.Port):
    """I am an TLS port."""
    
    transport = TLSServer

    def __init__(self, port, factory, credentials, backlog=50, interface='', reactor=None):
        tcp.Port.__init__(self, port, factory, backlog, interface, reactor)
        self.credentials = credentials

    def createInternetSocket(self):
        """(internal) create an SSL socket
        """
        sock = tcp.Port.createInternetSocket(self)
        return ServerSessionFactory(sock, self.credentials, AsyncServerSession)

    def _preMakeConnection(self, transport):
        def makeConnection(protocol, transport):
            pass
        protocol = transport.protocol
        transport._originalMakeConnection = protocol.makeConnection
        method = new.instancemethod(makeConnection, protocol, protocol.__class__)
        protocol.makeConnection = method
        transport.startTLS()
        return tcp.Port._preMakeConnection(self, transport)

def connectTLS(reactor, host, port, factory, credentials, timeout=30, bindAddress=None):
    c = TLSConnector(host, port, factory, credentials, timeout, bindAddress, reactor)
    c.connect()
    return c


def listenTLS(reactor, port, factory, credentials, backlog=50, interface=''):
    p = TLSPort(port, factory, credentials, backlog, interface, reactor)
    p.startListening()
    return p

## Add the connectTLS and listenTLS methods to the reactor

import new
from twisted.internet.posixbase import PosixReactorBase

method = new.instancemethod(connectTLS, None, PosixReactorBase)
setattr(PosixReactorBase, 'connectTLS', method)

method = new.instancemethod(listenTLS, None, PosixReactorBase)
setattr(PosixReactorBase, 'listenTLS', method)
