# Copyright (C) 2007-2008 AG Projects. See LICENSE for details.
#

"""GNUTLS Twisted interface"""

__all__ = ['X509Credentials', 'connectTLS', 'listenTLS']

from time import time

from twisted.python import failure
from twisted.internet import main, base, interfaces, abstract, tcp, error

from zope.interface import implementsOnly, implementedBy

from gnutls.connection import ClientSession, ServerSession, ServerSessionFactory
from gnutls.connection import X509Credentials as _X509Credentials
from gnutls.constants import SHUT_RDWR, SHUT_WR
from gnutls.errors import *


class KeepRunning:
    """Return this class from a recurrent function to indicate that it should keep running"""
    pass

class RecurrentCall(object):
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
        """Verifies the peer certificate and raises an exception if it cannot be accepted"""
        if isinstance(preverify_status, Exception):
            raise preverify_status
        self.check_certificate(peer_cert, cert_name='peer certificate')


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

    def _sendCloseReason(self, reason):
        try:
            self.socket.send_alert(reason)
        except OperationInterrupted:
            self._sendCloseReason(reason)

    def _sendCloseAlert(self, how=SHUT_RDWR):
        try:
            self.socket.bye(how)
        except OperationInterrupted:
            self._sendCloseAlert(how)

    def closeTLSSession(self, reason):
        try:
            self._sendCloseReason(reason)
            self._sendCloseAlert(SHUT_RDWR)
        except Exception:
            pass

    def _postLoseConnection(self):
        self.closeTLSSession(self._close_reason)
        return self._close_reason

    def endTLSWrite(self):
        self.stopWriting()
        try:
            self._sendCloseAlert(SHUT_WR)
        except OperationWouldBlock, e:
            if self.socket.interrupted_while_writing:
                self.startWriting()
                return
        except Exception, e:
            return e
        del self.doWrite

    def _closeWriteConnection(self):
        self.doWrite = self.endTLSWrite
        result = self.endTLSWrite()
        if isinstance(result, Exception):
            return result
        return tcp.Connection._closeWriteConnection(self)


class TLSClient(TLSMixin, tcp.Client):
    """Add TLS capabilities to a TCP client"""
    
    implementsOnly(interfaces.ISSLTransport, *[i for i in implementedBy(tcp.Client) if i != interfaces.ITLSTransport])
    
    def __init__(self, host, port, bindAddress, credentials, connector, reactor=None, server_name=None):
        self.credentials = credentials
        self.server_name = server_name
        self.__watchdog = None
        tcp.Client.__init__(self, host, port, bindAddress, connector, reactor)

    def createInternetSocket(self):
        sock = tcp.Client.createInternetSocket(self)
        return ClientSession(sock, self.credentials, self.server_name)

    def _recurrentVerify(self):
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
            self.__watchdog = RecurrentCall(credentials.verify_period, self._recurrentVerify)

    def doHandshake(self):
        self.stopWriting()
        try:
            self.socket.handshake()
        except (OperationWouldBlock, OperationInterrupted):
            if self.socket.interrupted_while_writing:
                self.startWriting()
            return
        except GNUTLSError, e:
            del self.doRead
            self.failIfNotConnected(err = e)
            return
        
        ## reset any references to the old doRead
        del self.doRead
        self.stopReading()
        
        try:
            self._verifyPeer()
        except GNUTLSError, e:
            self.closeTLSSession(e)
            self.failIfNotConnected(err = e)
            return
        except Exception, e:
            self.closeTLSSession(e)
            self.failIfNotConnected(err = error.getConnectError(str(e)))
            return
        
        ## TLS handshake (including certificate verification) finished succesfully
        tcp.Client._connectDone(self)
        
    def startTLS(self):
        self.doRead = self.doHandshake
        self.startReading()
        self.doHandshake()

    def _connectDone(self):
        self.startTLS()

    def loseConnection(self, reason=failure.Failure(main.CONNECTION_DONE)):
        reason = failure.Failure(reason) # accept python exceptions too
        self._close_reason = reason.value
        abstract.FileDescriptor.loseConnection(self, reason)

    def connectionLost(self, reason):
        if self.__watchdog is not None:
            self.__watchdog.cancel()
            self.__watchdog = None
        tcp.Client.connectionLost(self, reason)


class TLSConnector(base.BaseConnector):
    def __init__(self, host, port, factory, credentials, timeout, bindAddress, reactor=None, server_name=None):
        self.host = host
        self.port = port
        self.bindAddress = bindAddress
        self.credentials = credentials
        self.server_name = server_name
        base.BaseConnector.__init__(self, factory, timeout, reactor)

    def _makeTransport(self):
        return TLSClient(self.host, self.port, self.bindAddress, self.credentials, self, self.reactor, self.server_name)


class TLSServer(TLSMixin, tcp.Server):
    """Add TLS capabilities to a TCP server"""
    
    implementsOnly(interfaces.ISSLTransport, *[i for i in implementedBy(tcp.Server) if i != interfaces.ITLSTransport])
    
    def __init__(self, sock, protocol, client, server, sessionno, *args, **kw):
        self.__watchdog = None
        self.credentials = server.credentials
        tcp.Server.__init__(self, sock, protocol, client, server, sessionno, *args, **kw)
        self.protocol.makeConnection = lambda *args: None
        self.protocol.transport = self ## because we may call connectionLost without connectionMade
        self.startTLS()

    def _recurrentVerify(self):
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
            self.__watchdog = RecurrentCall(credentials.verify_period, self._recurrentVerify)

    def doHandshake(self):
        self.stopWriting()
        try:
            self.socket.handshake()
        except (OperationWouldBlock, OperationInterrupted):
            if self.socket.interrupted_while_writing:
                self.startWriting()
            return
        except GNUTLSError, e:
            del self.doRead
            return e
        
        ## reset any references to the old doRead
        del self.doRead
        self.stopReading()
        self.startReading()
        
        try:
            self._verifyPeer()
        except Exception, e:
            self.loseConnection(e)
            return
        
        ## TLS handshake (including certificate verification) finished succesfully
        
        del self.protocol.makeConnection
        self.protocol.makeConnection(self)

    def startTLS(self):
        self.doRead = self.doHandshake
        self.startReading()

    def loseConnection(self, reason=failure.Failure(main.CONNECTION_DONE)):
        reason = failure.Failure(reason) # accept python exceptions too
        self._close_reason = reason.value
        abstract.FileDescriptor.loseConnection(self, reason)

    def connectionLost(self, reason):
        if self.__watchdog is not None:
            self.__watchdog.cancel()
            self.__watchdog = None
        tcp.Server.connectionLost(self, reason)


class TLSPort(tcp.Port):
    """Add TLS capabilities to a TCP port"""

    transport = TLSServer

    def __init__(self, port, factory, credentials, backlog=50, interface='', reactor=None, session_class=ServerSession):
        tcp.Port.__init__(self, port, factory, backlog, interface, reactor)
        self.credentials = credentials
        self.session_class = session_class

    def createInternetSocket(self):
        sock = tcp.Port.createInternetSocket(self)
        return ServerSessionFactory(sock, self.credentials, self.session_class)


def connectTLS(reactor, host, port, factory, credentials, timeout=30, bindAddress=None, server_name=None):
    c = TLSConnector(host, port, factory, credentials, timeout, bindAddress, reactor, server_name)
    c.connect()
    return c


def listenTLS(reactor, port, factory, credentials, backlog=50, interface='', session_class=ServerSession):
    p = TLSPort(port, factory, credentials, backlog, interface, reactor, session_class)
    p.startListening()
    return p

## Add the connectTLS and listenTLS methods to the reactor

import new
from twisted.internet.posixbase import PosixReactorBase

method = new.instancemethod(connectTLS, None, PosixReactorBase)
setattr(PosixReactorBase, 'connectTLS', method)

method = new.instancemethod(listenTLS, None, PosixReactorBase)
setattr(PosixReactorBase, 'listenTLS', method)

