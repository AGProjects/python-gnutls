# Copyright (C) 2007 AG Projects
#

"""GNUTLS Twisted interface"""

__all__ = ['AsyncClientSession', 'AsyncServerSession', 'TLSMixin', 'TLSClient',
           'TLSServer', 'TLSConnector', 'TLSPort', 'connectTLS', 'listenTLS']

import socket
try:
    import fcntl
except ImportError:
    fcntl = None

from errno import EWOULDBLOCK, EINTR

from twisted.python import failure
from twisted.internet import main, base, address, tcp, error
from twisted.internet.protocol import BaseProtocol

from gnutls.connection import *
from gnutls.errors import *


class AsyncClientSession(ClientSession):

    def recv(self, bufsize):
        try:
            return ClientSession.recv(self, bufsize)
        except OperationWouldBlock, e:
            raise socket.error(EWOULDBLOCK)
        except OperationInterrupted, e:
            raise socket.error(EINTR)
        except GNUTLSError:
            return ''

    def send(self, buffer):
        try:
            return ClientSession.send(self, str(buffer))
        except OperationWouldBlock, e:
            raise socket.error(EWOULDBLOCK)
        except OperationInterrupted, e:
            raise socket.error(EINTR)
        except GNUTLSError:
            return -1


class AsyncServerSession(ServerSession):

    def recv(self, bufsize):
        try:
            return ServerSession.recv(self, bufsize)
        except OperationWouldBlock, e:
            raise socket.error(EWOULDBLOCK)
        except OperationInterrupted, e:
            raise socket.error(EINTR)
        except GNUTLSError:
            return ''

    def send(self, buffer):
        try:
            return ServerSession.send(self, str(buffer))
        except OperationWouldBlock, e:
            raise socket.error(EWOULDBLOCK)
        except OperationInterrupted, e:
            raise socket.error(EINTR)
        except GNUTLSError:
            return -1


class TLSMixin:
    """TLS specific functionality common to both clients and servers"""

    def getPeerCertificate(self):
        return self.socket.peer_certificate

    def _postLoseConnection(self):
        self.doRead = self._sendBye
        self.startReading()
        return self._sendBye()

    def _sendBye(self):
        try:
            self.socket.bye()
        except OperationWouldBlock, e:
            return None
        except GNUTLSError, e:
            return e
        self.stopReading()
        del self.doRead
        return getattr(self, '_close_reason', main.CONNECTION_DONE)


class TLSClient(TLSMixin, tcp.Client):
    """I am an TLS client."""
    
    def __init__(self, host, port, bindAddress, credentials, connector, reactor=None):
        self.credentials = credentials
        tcp.Client.__init__(self, host, port, bindAddress, connector, reactor)

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
        except OperationWouldBlock, e:
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
        self.startReading()
        self.doHandshake()

    def _connectDone(self):
        self.startTLS()

    def loseConnection(self, reason=main.CONNECTION_DONE):
        self._close_reason = reason
        tcp.Client.loseConnection(self, failure.Failure(reason))


class TLSConnector(base.BaseConnector):
    def __init__(self, host, port, factory, credentials, timeout, bindAddress, reactor=None):
        self.host = host
        self.port = port
        self.bindAddress = bindAddress
        self.credentials = credentials
        base.BaseConnector.__init__(self, factory, timeout, reactor)

    def _makeTransport(self):
        return TLSClient(self.host, self.port, self.bindAddress, self.credentials, self, self.reactor)


class TLSServer(TLSMixin, tcp.Server):
    """I am an TLS server.
    
    I am a serverside network connection transport; a socket which came from an
    accept() on a server.
    """

    def doHandshake(self):
        try:
            self.socket.handshake()
        except OperationWouldBlock, e:
            return
        except GNUTLSError, e:
            return e
        
        # verify peer after the handshake was completed
        try:
            self.socket.verify_peer()
        except (GNUTLSError, CertificateError), e:
            self.loseConnection(e)
            return
        
        # If I have reached this point without raising or returning, that means
        # that the handshake has finished succesfully.
        del self.doRead
        # we first stop and then start, to reset any references to the old doRead
        self.stopReading()
        self.startReading()
        del self.protocol.makeConnection
        self.protocol.makeConnection(self)

    def startTLS(self):
        self.doRead = self.doHandshake
        self.startReading()

    def loseConnection(self, reason=main.CONNECTION_DONE):
        self._close_reason = reason
        tcp.Server.loseConnection(self, failure.Failure(reason))


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
        transport.protocol.makeConnection = lambda *args: None
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

