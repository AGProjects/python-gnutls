# Copyright (C) 2007 AG Projects
#

"""GNUTLS errors"""

__all__ = ['Error', 'GNUTLSError', 'OperationWouldBlock', 'OperationInterrupted', 'CertificateError']

class Error(Exception): pass

class GNUTLSError(Error): pass
class OperationWouldBlock(GNUTLSError): pass
class OperationInterrupted(GNUTLSError): pass

class CertificateError(Error): pass

