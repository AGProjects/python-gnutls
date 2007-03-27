# Copyright (C) 2007 AG Projects
#

"""GNUTLS Twisted interface"""

__all__ = ['X509Credentials', 'connectTLS', 'listenTLS']

import socket
from time import time
from errno import EWOULDBLOCK, EINTR

from twisted.python import failure
from twisted.internet import main, base, address, tcp, error
from twisted.internet.protocol import BaseProtocol

from gnutls.connection import ClientSession, ServerSession, ServerSessionFactory
from gnutls.connection import X509Credentials as _X509Credentials
from gnutls.errors import *


class KeepRunning:
    """Return this class from a recurent function to indicate that it should keep running"""
    pass

class RecurentCall(object):
    """Execute a function repeatedly at the given interval, until signaled to stop"""
    def __init__(self, period, func, *args, **kwargs):
        from twisted.internet import reactor
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.period = period
        self.now = None
        self.next = None
        self.callid = reactor.callLater(period, self)
    def __call__(self):
        from twisted.internet import reactor
        self.callid = None
        if self.now is None:
            self.now = time()
            self.next = self.now + self.period
        else:
            self.now, self.next = self.next, self.next + self.period
        result = self.func(*self.args, **self.kwargs)
        if result is KeepRunning:
            delay = max(self.next-time(), 0)
            self.callid = reactor.callLater(delay, self)
    def cancel(self):
        if self.callid is not None:
            try:
                self.callid.cancel()
            except ValueError:
                pass
            self.callid = None


class CertificateOK: pass

class X509Credentials(_X509Credentials):
    """A Twisted enhanced X509Credentials"""
    verify_peer = False
    verify_period = None

    def verify_callback(self, peer_cert, preverify_status=None):
        """Verifies peer certificate and raises an exception if it cannot be accepted"""
        if isinstance(preverify_status, Exception):
            raise preverify_status
        self.check_certificate(peer_cert)
        


class TLSMixin:
    """TLS specific functionality common to both clients and servers"""

    def getPeerCertificate(self):
        return self.socket.peer_certificate

    def doRead(self):
        try:
            return tcp.Connection.doRead(self)
        except (OperationWouldBlock, OperationInterrupted):
            return
        except GNUTLSError, e:
            return e

    def writeSomeData(self, data):
        try:
            return tcp.Connection.writeSomeData(self, data)
        except OperationInterrupted:
            return self.writeSomeData(data)
        except OperationWouldBlock:
            return 0
        except GNUTLSError, e:
            return e

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
    """Add TLS capabilities to a TCP client"""
    
    def __init__(self, host, port, bindAddress, credentials, connector, reactor=None):
        self.credentials = credentials
        self.__watchdog = None
        tcp.Client.__init__(self, host, port, bindAddress, connector, reactor)

    def createInternetSocket(self):
        sock = tcp.Client.createInternetSocket(self)
        return ClientSession(sock, self.credentials)

    def _recurentVerify(self):
        if not self.connected or self.disconnecting:
            return
        try:
            self.credentials.verify_callback(self.socket.peer_certificate)
        except Exception, e:
            self.loseConnection(e)
            return
        else:
            return KeepRunning

    def _verifyPeer(self):
        session = self.socket
        credentials = self.credentials
        if not credentials.verify_peer:
            return
        try:
            session.verify_peer()
        except Exception, e:
            preverify_status = e
        else:
            preverify_status = CertificateOK
        
        credentials.verify_callback(session.peer_certificate, preverify_status)
        
        if credentials.verify_period > 0:
            self.__watchdog = RecurentCall(credentials.verify_period, self._recurentVerify)

    def doHandshake(self):
        self.stopWriting()
        try:
            self.socket.handshake()
        except (OperationWouldBlock, OperationInterrupted):
            if self.socket.interrupted_while_writing:
                self.startWriting()
            return
        except GNUTLSError, e:
            self.failIfNotConnected(err = error.getConnectError(str(e)))
            return
        
        try:
            self._verifyPeer()
        except Exception, e:
            self.failIfNotConnected(err = error.getConnectError(str(e)))
            return
        
        ## TLS handshake (including certificate verification) finished succesfully
        
        del self.doRead
        ## reset any references to the old doRead by stopping and starting
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

    def connectionLost(self, reason):
        if self.__watchdog is not None:
            self.__watchdog.cancel()
            self.__watchdog = None
        tcp.Client.connectionLost(self, reason)


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
    """Add TLS capabilities to a TCP server"""
    
    def __init__(self, sock, protocol, client, server, sessionno):
        self.__watchdog = None
        self.credentials = server.credentials
        tcp.Server.__init__(self, sock, protocol, client, server, sessionno)

    def _recurentVerify(self):
        if not self.connected or self.disconnecting:
            return
        try:
            self.credentials.verify_callback(self.socket.peer_certificate)
        except Exception, e:
            self.loseConnection(e)
            return
        else:
            return KeepRunning

    def _verifyPeer(self):
        session = self.socket
        credentials = self.credentials
        if not credentials.verify_peer:
            return
        try:
            session.verify_peer()
        except Exception, e:
            preverify_status = e
        else:
            preverify_status = CertificateOK
        
        credentials.verify_callback(session.peer_certificate, preverify_status)
        
        if credentials.verify_period > 0:
            self.__watchdog = RecurentCall(credentials.verify_period, self._recurentVerify)

    def doHandshake(self):
        self.stopWriting()
        try:
            self.socket.handshake()
        except (OperationWouldBlock, OperationInterrupted):
            if self.socket.interrupted_while_writing:
                self.startWriting()
            return
        except GNUTLSError, e:
            return e
        
        try:
            self._verifyPeer()
        except Exception, e:
            self.loseConnection(e)
            return
        
        ## TLS handshake (including certificate verification) finished succesfully
        
        del self.doRead
        ## reset any references to the old doRead by stopping and starting
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

    def connectionLost(self, reason):
        if self.__watchdog is not None:
            self.__watchdog.cancel()
            self.__watchdog = None
        tcp.Server.connectionLost(self, reason)


class TLSPort(tcp.Port):
    """Add TLS capabilities to a TCP port"""
    
    transport = TLSServer

    def __init__(self, port, factory, credentials, backlog=50, interface='', reactor=None):
        tcp.Port.__init__(self, port, factory, backlog, interface, reactor)
        self.credentials = credentials

    def createInternetSocket(self):
        sock = tcp.Port.createInternetSocket(self)
        return ServerSessionFactory(sock, self.credentials, ServerSession)

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

